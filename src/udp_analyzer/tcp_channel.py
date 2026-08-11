from __future__ import annotations

import json
import os
import re
import select
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from .channels import ChannelCatalog, ChannelTarget
from .ebpf import CommandRunner, ifname_from_index, ipv4_from_bpf_int, raw_bytes
from .models import bucket_start_ns


TCP_PROTO = 6
TCP_CHANNEL_MAP_NAME = "tcp_channel_flows"


@dataclass(frozen=True)
class TcpFlowKey:
    socket_cookie: int
    src_ip4: int
    dst_ip4: int
    src_port: int
    dst_port: int
    family: int
    ip_proto: int
    cgroup_id: int

    @property
    def src_ip(self) -> str:
        return ipv4_from_bpf_int(self.src_ip4)

    @property
    def dst_ip(self) -> str:
        return ipv4_from_bpf_int(self.dst_ip4)

    def identity(self) -> tuple[int, int, int, int, int, int, int, int]:
        return (
            self.socket_cookie,
            self.src_ip4,
            self.dst_ip4,
            self.src_port,
            self.dst_port,
            self.family,
            self.ip_proto,
            self.cgroup_id,
        )


@dataclass(frozen=True)
class TcpFlowCounters:
    tx_bytes: int
    rx_bytes: int
    tx_calls: int
    rx_calls: int
    connections: int


@dataclass(frozen=True)
class TcpFlowValue:
    tx_bytes: int
    rx_bytes: int
    tx_calls: int
    rx_calls: int
    connections: int
    start_ns: int
    last_ns: int
    pid: int
    ifindex: int
    state: int

    @property
    def counters(self) -> TcpFlowCounters:
        return TcpFlowCounters(
            tx_bytes=self.tx_bytes,
            rx_bytes=self.rx_bytes,
            tx_calls=self.tx_calls,
            rx_calls=self.rx_calls,
            connections=self.connections,
        )


@dataclass(frozen=True)
class TcpFlowEntry:
    key: TcpFlowKey
    value: TcpFlowValue


@dataclass(frozen=True)
class ChannelTcpSample:
    bucket_start_ns: int
    bucket_ms: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    socket_id: int
    cgroup_id: int
    tx_bytes: int
    rx_bytes: int
    tx_calls: int
    rx_calls: int
    connections: int
    unit: str = ""
    channel: str = ""
    url: str = ""
    host: str = ""
    ifindex: int = 0
    ifname: str = ""
    host_pid: int = 0
    state: int = 0
    status: str = "unknown_unit"
    layer: str = "tcp_channel"
    ip_proto: int = TCP_PROTO

    @property
    def bucket_start_iso(self) -> str:
        seconds = self.bucket_start_ns / 1_000_000_000
        return (
            datetime.fromtimestamp(seconds, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def to_dict(self) -> dict[str, Union[int, str]]:
        return {
            "ts": self.bucket_start_iso,
            "bucket_start_ns": self.bucket_start_ns,
            "bucket_ms": self.bucket_ms,
            "layer": self.layer,
            "channel": self.channel,
            "unit": self.unit,
            "url": self.url,
            "host": self.host,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "ip_proto": self.ip_proto,
            "ifindex": self.ifindex,
            "ifname": self.ifname,
            "host_pid": self.host_pid,
            "socket_id": self.socket_id,
            "cgroup_id": self.cgroup_id,
            "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes,
            "tx_calls": self.tx_calls,
            "rx_calls": self.rx_calls,
            "connections": self.connections,
            "status": self.status,
            "tcp_state": self.state,
            "bytes": self.tx_bytes + self.rx_bytes,
            # Compatibility field for UDP-row consumers. TCP syscall hooks do not
            # see packets, so report the syscall count instead of a hardcoded 0:
            # downstream liveness checks divide packets by the interval to get a
            # rate, and a permanent 0 reads as "stream not flowing" forever even
            # while bytes keep climbing.
            "packets": self.rx_calls + self.tx_calls,
        }


@dataclass(frozen=True)
class ChannelSampleFilter:
    channel: Optional[str] = None
    unit: Optional[str] = None
    host: Optional[str] = None
    status: Optional[str] = None

    def matches(self, sample: ChannelTcpSample) -> bool:
        checks = (
            self.channel is None or sample.channel == self.channel,
            self.unit is None or sample.unit == self.unit,
            self.host is None or sample.host == self.host,
            self.status is None or sample.status == self.status,
        )
        return all(checks)


@dataclass(frozen=True)
class TcpChannelLoaderStatus:
    map_id: int


#: BTF source used to check the kernel's tcp_recvmsg prototype (world-readable).
KERNEL_BTF_PATH = "/sys/kernel/btf/vmlinux"


def kernel_tcp_recvmsg_has_nonblock(btf_text: Optional[str] = None) -> Optional[bool]:
    """True = kernel exposes the pre-5.19 tcp_recvmsg(..., int nonblock, ...).

    Commit ec095263a965 (5.19) dropped the `nonblock` parameter; our fexit
    program declares the NEW signature. On the old one the verifier still
    accepts the program, but the slot read as `ret` is really the addr_len
    pointer. None = cannot determine (no bpftool / no BTF) — the caller
    decides how brave to be.
    """
    if btf_text is None:
        try:
            # RAW dump, not `format c`: the C form is vmlinux.h — types only,
            # no function prototypes — so grepping it can never find the
            # answer. The raw form lists FUNC/FUNC_PROTO entries with
            # parameter names (verified against a live 6.8 kernel).
            proc = subprocess.run(
                ["bpftool", "btf", "dump", "file", KERNEL_BTF_PATH],
                capture_output=True, text=True, timeout=120,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0 or not proc.stdout:
            return None
        btf_text = proc.stdout
    func = re.search(r"FUNC 'tcp_recvmsg' type_id=(\d+)", btf_text)
    if not func:
        return None
    proto = re.search(
        rf"^\[{func.group(1)}\] FUNC_PROTO[^\n]*((?:\n\t[^\n]*)*)",
        btf_text, re.M,
    )
    if not proto:
        return None
    return "'nonblock'" in proto.group(1)


def refuse_pre519_tcp_recvmsg() -> None:
    """Hard gate before attach; see kernel_tcp_recvmsg_has_nonblock."""
    has_nonblock = kernel_tcp_recvmsg_has_nonblock()
    if has_nonblock:
        raise RuntimeError(
            "kernel tcp_recvmsg has the pre-5.19 signature (nonblock parameter): "
            "the fexit program would silently account garbage as rx_bytes. "
            "TCP channel attribution requires kernel >= 5.19."
        )


class TcpChannelBpfAttachment:
    def __init__(
        self,
        loader_path: Path,
        object_path: Path,
        startup_timeout: float = 10.0,
    ):
        self.loader_path = loader_path
        self.object_path = object_path
        self.startup_timeout = startup_timeout
        self.process: Optional[subprocess.Popen[str]] = None
        self.status: Optional[TcpChannelLoaderStatus] = None
        self.stderr_file: Optional[Any] = None

    def attach(self) -> TcpChannelLoaderStatus:
        if not self.loader_path.exists():
            raise RuntimeError(f"TCP channel BPF loader does not exist: {self.loader_path}")
        if not self.object_path.exists():
            raise RuntimeError(f"TCP channel BPF object does not exist: {self.object_path}")
        # Refuse kernels with the pre-5.19 tcp_recvmsg signature BEFORE attaching.
        # fexit validates argument access against the KERNEL prototype, so on an
        # old kernel the program loads cleanly but reads the addr_len POINTER as
        # "ret": rx_bytes then accumulates pointer values — huge garbage counters
        # with no error anywhere. A hard refusal here is the only honest signal.
        refuse_pre519_tcp_recvmsg()

        command = [str(self.loader_path), str(self.object_path)]
        if os.geteuid() != 0:
            command = ["sudo", "-n", *command]
        try:
            self.stderr_file = tempfile.TemporaryFile(mode="w+t")
            self.process = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=self.stderr_file,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            self._close_stderr()
            raise RuntimeError(f"required command not found: {command[0]}") from exc
        except PermissionError as exc:
            self._close_stderr()
            raise RuntimeError(f"permission denied running: {command[0]}") from exc

        assert self.process.stdout is not None
        ready, _, _ = select.select(
            [self.process.stdout], [], [], self.startup_timeout
        )
        if not ready:
            self.detach()
            raise RuntimeError(
                "TCP channel BPF loader did not report readiness within "
                f"{self.startup_timeout:g}s"
            )

        line = self.process.stdout.readline()
        if not line:
            self.process.wait()
            detail = self._stderr_text() or f"exit status {self.process.returncode}"
            self.process = None
            self._close_stderr()
            raise RuntimeError(f"TCP channel BPF attach failed: {detail}")

        self.status = parse_tcp_channel_loader_status(line)
        return self.status

    def ensure_alive(self) -> None:
        process = self.process
        if process is None:
            raise RuntimeError("TCP channel BPF loader is not running")
        returncode = process.poll()
        if returncode is None:
            return
        detail = self._stderr_text()
        self.process = None
        self.status = None
        self._close_stderr()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"TCP channel BPF loader exited with status {returncode}{suffix}"
        )

    def detach(self) -> None:
        process = self.process
        self.process = None
        self.status = None
        if process is None:
            self._close_stderr()
            return
        if process.poll() is not None:
            self._close_stderr()
            return
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        self._close_stderr()

    def _stderr_text(self) -> str:
        if self.stderr_file is None:
            return ""
        self.stderr_file.flush()
        self.stderr_file.seek(0)
        return self.stderr_file.read().strip()

    def _close_stderr(self) -> None:
        if self.stderr_file is not None:
            self.stderr_file.close()
            self.stderr_file = None


class BpftoolTcpChannelMapReader:
    def __init__(self, map_id: int, runner: Optional[CommandRunner] = None):
        if map_id <= 0:
            raise RuntimeError(f"invalid TCP channel map id: {map_id}")
        self.map_id = map_id
        self.runner = runner or CommandRunner()

    def dump_entries(self) -> list[TcpFlowEntry]:
        raw_entries = self.runner.run_json(
            ["bpftool", "-j", "map", "dump", "id", str(self.map_id)], sudo=True
        )
        if raw_entries is None:
            return []
        return [parse_tcp_flow_entry(entry) for entry in raw_entries]


class TcpChannelCollector:
    def __init__(
        self,
        catalog: ChannelCatalog,
        bucket_ms: int,
        sample_filter: Optional[ChannelSampleFilter] = None,
        object_path: Path = Path("bpf/tcp_channel.bpf.o"),
        loader_path: Path = Path("bpf/tcp_channel_loader"),
        map_id: Optional[int] = None,
        attach: bool = True,
        proc_root: Path = Path("/proc"),
    ):
        self.catalog = catalog
        self.bucket_ms = bucket_ms
        self.sample_filter = sample_filter or ChannelSampleFilter()
        self.proc_root = proc_root
        self.previous: dict[tuple[int, int, int, int, int, int, int, int], TcpFlowCounters] = {}
        self.pid_units: dict[int, str] = {}
        self.attachment: Optional[TcpChannelBpfAttachment] = None
        if attach:
            self.attachment = TcpChannelBpfAttachment(
                loader_path=loader_path,
                object_path=object_path,
            )
            status = self.attachment.attach()
            map_id = status.map_id
        if map_id is None:
            raise RuntimeError("--tcp-map-id is required with --no-attach")
        self.reader = BpftoolTcpChannelMapReader(map_id)

    def read_checkpoint(self) -> list[ChannelTcpSample]:
        if self.attachment is not None:
            self.attachment.ensure_alive()
        # Drop the pid->unit cache every checkpoint. A cache kept for the process
        # lifetime returns the PREVIOUS owner after pid reuse and pins a transient
        # /proc miss as "" forever; one /proc read per live pid per tick is cheap
        # next to the bpftool dump we just did.
        self.pid_units.clear()
        now_ns = time.time_ns()
        bucket_ns = bucket_start_ns(now_ns, self.bucket_ms)
        previous_ns = getattr(self, "_last_checkpoint_ns", None)
        self._last_checkpoint_ns = now_ns
        elapsed_ms = self.bucket_ms
        if previous_ns is not None:
            measured = (now_ns - previous_ns) // 1_000_000
            if measured > 0:
                elapsed_ms = int(measured)
        return self._read_flows(bucket_ns=bucket_ns, elapsed_ms=elapsed_ms)

    def _read_flows(self, bucket_ns: int, elapsed_ms: int) -> list[ChannelTcpSample]:
        totals: dict[tuple[int, int, int, int, int, int, int, int], TcpFlowCounters] = {}
        first_entry: dict[tuple[int, int, int, int, int, int, int, int], TcpFlowEntry] = {}
        for entry in self.reader.dump_entries():
            identity = entry.key.identity()
            counters = entry.value.counters
            previous = totals.get(identity)
            totals[identity] = TcpFlowCounters(
                tx_bytes=(previous.tx_bytes if previous else 0) + counters.tx_bytes,
                rx_bytes=(previous.rx_bytes if previous else 0) + counters.rx_bytes,
                tx_calls=(previous.tx_calls if previous else 0) + counters.tx_calls,
                rx_calls=(previous.rx_calls if previous else 0) + counters.rx_calls,
                connections=(previous.connections if previous else 0)
                + counters.connections,
            )
            first_entry.setdefault(identity, entry)

        for stale in set(self.previous) - set(totals):
            del self.previous[stale]

        samples = []
        for identity, counters in totals.items():
            entry = first_entry[identity]
            known = identity in self.previous
            previous = self.previous.get(
                identity,
                TcpFlowCounters(
                    tx_bytes=0,
                    rx_bytes=0,
                    tx_calls=0,
                    rx_calls=0,
                    connections=0,
                ),
            )
            self.previous[identity] = counters
            if not known:
                continue

            # Tolerate counter regressions instead of raising: a reloaded map
            # (loader restart under --no-attach) or a recycled identity would
            # otherwise KILL the collector mid-run — the UDP path already
            # clamps for exactly this reason. The clamped interval undercounts;
            # the next one is correct because the baseline was just replaced.
            tx_delta = max(counters.tx_bytes - previous.tx_bytes, 0)
            rx_delta = max(counters.rx_bytes - previous.rx_bytes, 0)
            tx_calls_delta = max(counters.tx_calls - previous.tx_calls, 0)
            rx_calls_delta = max(counters.rx_calls - previous.rx_calls, 0)
            connections_delta = max(counters.connections - previous.connections, 0)
            if (
                tx_delta <= 0
                and rx_delta <= 0
                and tx_calls_delta <= 0
                and rx_calls_delta <= 0
                and connections_delta <= 0
            ):
                continue

            unit = self._unit_for_pid(entry.value.pid)
            match = self.catalog.match(unit, entry.key.dst_ip, entry.key.dst_port)
            target = match.target
            sample = ChannelTcpSample(
                bucket_start_ns=bucket_ns,
                bucket_ms=elapsed_ms,
                src_ip=entry.key.src_ip,
                dst_ip=entry.key.dst_ip,
                src_port=entry.key.src_port,
                dst_port=entry.key.dst_port,
                socket_id=entry.key.socket_cookie,
                cgroup_id=entry.key.cgroup_id,
                tx_bytes=tx_delta,
                rx_bytes=rx_delta,
                tx_calls=tx_calls_delta,
                rx_calls=rx_calls_delta,
                connections=connections_delta,
                unit=unit,
                channel=target.channel if target else "",
                url=target.url if target else "",
                host=target.host if target else "",
                ifindex=entry.value.ifindex,
                ifname=ifname_from_index(entry.value.ifindex, ""),
                host_pid=entry.value.pid,
                state=entry.value.state,
                status=match.status,
            )
            if self.sample_filter.matches(sample):
                samples.append(sample)
        return samples

    def _unit_for_pid(self, pid: int) -> str:
        if pid <= 0:
            return ""
        cached = self.pid_units.get(pid)
        if cached is not None:
            return cached
        unit = unit_for_pid(pid, proc_root=self.proc_root)
        self.pid_units[pid] = unit
        return unit

    def close(self) -> None:
        if self.attachment is not None:
            self.attachment.detach()


class TcpChannelDryRunCollector:
    def __init__(
        self,
        catalog: ChannelCatalog,
        bucket_ms: int,
        sample_filter: Optional[ChannelSampleFilter] = None,
    ):
        self.catalog = catalog
        self.bucket_ms = bucket_ms
        self.sample_filter = sample_filter or ChannelSampleFilter()
        self.tick = 0

    def read_checkpoint(self) -> list[ChannelTcpSample]:
        now_ns = time.time_ns()
        bucket_ns = bucket_start_ns(now_ns, self.bucket_ms)
        self.tick += 1
        target = self.catalog.targets[0] if self.catalog.targets else demo_target()
        sample = ChannelTcpSample(
            bucket_start_ns=bucket_ns,
            bucket_ms=self.bucket_ms,
            src_ip="10.0.0.10",
            dst_ip=target.addresses[0] if target.addresses else "203.0.113.10",
            src_port=40000 + self.tick,
            dst_port=target.port,
            socket_id=900000 + self.tick,
            cgroup_id=12345,
            tx_bytes=1200 + self.tick,
            rx_bytes=64000 + self.tick,
            tx_calls=2,
            rx_calls=8,
            connections=1 if self.tick == 1 else 0,
            unit=target.unit,
            channel=target.channel,
            url=target.url,
            host=target.host,
            host_pid=4242,
            status="matched",
        )
        return [sample] if self.sample_filter.matches(sample) else []

    def close(self) -> None:
        return None


def demo_target() -> ChannelTarget:
    return ChannelTarget(
        channel="demo-channel",
        unit="demo-channel.service",
        url="https://api.example.com/demo",
        scheme="https",
        host="api.example.com",
        port=443,
        path="/demo",
        addresses=("203.0.113.10",),
    )


def parse_tcp_channel_loader_status(line: str) -> TcpChannelLoaderStatus:
    try:
        raw = json.loads(line)
        map_id = int(raw["map_id"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"invalid TCP channel loader status: {line!r}") from exc
    if map_id <= 0:
        raise RuntimeError(f"invalid TCP channel loader status: {line!r}")
    return TcpChannelLoaderStatus(map_id=map_id)


def parse_tcp_flow_entry(entry: dict[str, Any]) -> TcpFlowEntry:
    return TcpFlowEntry(
        key=parse_tcp_flow_key(entry.get("key")),
        value=parse_tcp_flow_value(
            value=entry.get("value"),
            values=entry.get("values"),
        ),
    )


def parse_tcp_flow_key(raw_key: Any) -> TcpFlowKey:
    if isinstance(raw_key, dict):
        key = TcpFlowKey(
            socket_cookie=int(raw_key["socket_cookie"]),
            src_ip4=int(raw_key["src_ip4"]),
            dst_ip4=int(raw_key["dst_ip4"]),
            src_port=int(raw_key["src_port"]),
            dst_port=int(raw_key["dst_port"]),
            family=int(raw_key["family"]),
            ip_proto=int(raw_key["ip_proto"]),
            cgroup_id=int(raw_key["cgroup_id"]),
        )
        validate_tcp_flow_key(key)
        return key

    key_bytes = raw_bytes(raw_key)
    if len(key_bytes) < 32:
        raise RuntimeError(f"unexpected tcp_flow_key size from bpftool: {len(key_bytes)}")
    socket_cookie, src_ip4, dst_ip4, src_port, dst_port, family, ip_proto, cgroup_id = (
        struct.unpack("<QIIHHBB2xQ", key_bytes[:32])
    )
    key = TcpFlowKey(
        socket_cookie=socket_cookie,
        src_ip4=src_ip4,
        dst_ip4=dst_ip4,
        src_port=src_port,
        dst_port=dst_port,
        family=family,
        ip_proto=ip_proto,
        cgroup_id=cgroup_id,
    )
    validate_tcp_flow_key(key)
    return key


def validate_tcp_flow_key(key: TcpFlowKey) -> None:
    if key.socket_cookie <= 0:
        raise RuntimeError("TCP channel map contains a zero socket cookie")
    if key.family != socket.AF_INET or key.ip_proto != socket.IPPROTO_TCP:
        raise RuntimeError(
            "TCP channel map contains a non-IPv4-TCP key: "
            f"family={key.family} protocol={key.ip_proto}"
        )


def parse_tcp_flow_value(value: Any, values: Any) -> TcpFlowValue:
    if values is not None:
        tx_bytes = 0
        rx_bytes = 0
        tx_calls = 0
        rx_calls = 0
        connections = 0
        start_ns = 0
        last_ns = 0
        pid = 0
        ifindex = 0
        state = 0
        for cpu_value in values:
            parsed = parse_tcp_flow_value(value=cpu_value.get("value"), values=None)
            tx_bytes += parsed.tx_bytes
            rx_bytes += parsed.rx_bytes
            tx_calls += parsed.tx_calls
            rx_calls += parsed.rx_calls
            connections += parsed.connections
            start_ns = min_nonzero(start_ns, parsed.start_ns)
            last_ns = max(last_ns, parsed.last_ns)
            pid = pid or parsed.pid
            ifindex = ifindex or parsed.ifindex
            state = state or parsed.state
        return TcpFlowValue(
            tx_bytes=tx_bytes,
            rx_bytes=rx_bytes,
            tx_calls=tx_calls,
            rx_calls=rx_calls,
            connections=connections,
            start_ns=start_ns,
            last_ns=last_ns,
            pid=pid,
            ifindex=ifindex,
            state=state,
        )

    if isinstance(value, dict):
        return TcpFlowValue(
            tx_bytes=int(value["tx_bytes"]),
            rx_bytes=int(value["rx_bytes"]),
            tx_calls=int(value["tx_calls"]),
            rx_calls=int(value["rx_calls"]),
            connections=int(value.get("connections", 0)),
            start_ns=int(value.get("start_ns", 0)),
            last_ns=int(value.get("last_ns", 0)),
            pid=int(value.get("pid", 0)),
            ifindex=int(value.get("ifindex", 0)),
            state=int(value.get("state", 0)),
        )

    value_bytes = raw_bytes(value)
    if len(value_bytes) < 72:
        raise RuntimeError(
            f"unexpected tcp_flow_value size from bpftool: {len(value_bytes)}"
        )
    (
        tx_bytes,
        rx_bytes,
        tx_calls,
        rx_calls,
        connections,
        start_ns,
        last_ns,
        pid,
        ifindex,
        state,
        _pad,
    ) = struct.unpack("<QQQQQQQIIII", value_bytes[:72])
    return TcpFlowValue(
        tx_bytes=tx_bytes,
        rx_bytes=rx_bytes,
        tx_calls=tx_calls,
        rx_calls=rx_calls,
        connections=connections,
        start_ns=start_ns,
        last_ns=last_ns,
        pid=pid,
        ifindex=ifindex,
        state=state,
    )


def min_nonzero(left: int, right: int) -> int:
    if not left:
        return right
    if not right:
        return left
    return min(left, right)


def unit_for_pid(pid: int, proc_root: Path = Path("/proc")) -> str:
    text = read_text(proc_root / str(pid) / "cgroup")
    return unit_from_cgroup_text(text)


def unit_from_cgroup_text(text: str) -> str:
    candidates = []
    for line in text.splitlines():
        try:
            path = line.rsplit(":", 1)[1]
        except IndexError:
            continue
        for part in path.split("/"):
            if part.endswith(".service") and not part.startswith("user@"):
                candidates.append(part)
    return candidates[-1] if candidates else ""


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
