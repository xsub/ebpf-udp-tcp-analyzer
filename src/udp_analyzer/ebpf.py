from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .models import SampleFilter, UdpSample, bucket_start_ns
from .processes import ProcessSocketEnricher


UDP_INGRESS_PROGRAM_NAME = "udp_ingress"
UDP_INGRESS_MAP_NAME = "udp_ingress_counters"
UDP_DELIVERED_MAP_NAME = "udp_delivered_counters"


@dataclass(frozen=True)
class UdpMapKey:
    family: int
    ip_proto: int
    src_port: int
    dst_port: int
    ifindex: int
    src_ip4: int
    dst_ip4: int

    @property
    def src_ip(self) -> str:
        return ipv4_from_bpf_int(self.src_ip4)

    @property
    def dst_ip(self) -> str:
        return ipv4_from_bpf_int(self.dst_ip4)

    def identity(self) -> tuple[int, int, int, int, int, int, int]:
        return (
            self.family,
            self.ip_proto,
            self.src_port,
            self.dst_port,
            self.ifindex,
            self.src_ip4,
            self.dst_ip4,
        )


@dataclass(frozen=True)
class UdpMapCounters:
    packets: int
    bytes: int


@dataclass(frozen=True)
class UdpMapEntry:
    key: UdpMapKey
    counters: UdpMapCounters


@dataclass(frozen=True)
class DeliveredMapKey:
    socket_cookie: int
    src_ip4: int
    dst_ip4: int
    src_port: int
    dst_port: int
    family: int
    ip_proto: int

    @property
    def src_ip(self) -> str:
        return ipv4_from_bpf_int(self.src_ip4)

    @property
    def dst_ip(self) -> str:
        return ipv4_from_bpf_int(self.dst_ip4)

    def identity(self) -> tuple[int, int, int, int, int, int, int]:
        return (
            self.socket_cookie,
            self.src_ip4,
            self.dst_ip4,
            self.src_port,
            self.dst_port,
            self.family,
            self.ip_proto,
        )


@dataclass(frozen=True)
class DeliveredMapValue:
    packets: int
    bytes: int
    socket_inode: int
    ifindex: int

    @property
    def counters(self) -> UdpMapCounters:
        return UdpMapCounters(packets=self.packets, bytes=self.bytes)


@dataclass(frozen=True)
class DeliveredMapEntry:
    key: DeliveredMapKey
    value: DeliveredMapValue


@dataclass(frozen=True)
class ReceiveLoaderStatus:
    backend: str
    map_id: int


def parse_receive_loader_status(line: str) -> ReceiveLoaderStatus:
    try:
        raw = json.loads(line)
        backend = str(raw["backend"])
        map_id = int(raw["map_id"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"invalid receive loader status: {line!r}") from exc
    if backend not in {"fentry", "kprobe"} or map_id <= 0:
        raise RuntimeError(f"invalid receive loader status: {line!r}")
    return ReceiveLoaderStatus(backend=backend, map_id=map_id)


class CommandRunner:
    def run_json(self, args: list[str], sudo: bool = False) -> Any:
        result = self.run(args, sudo=sudo)
        try:
            return json.loads(result.stdout or "null")
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"command did not return JSON: {' '.join(args)}\n{result.stdout}"
            ) from exc

    def run(
        self, args: list[str], sudo: bool = False, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        command = ["sudo", "-n", *args] if sudo else args
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"required command not found: {command[0]}") from exc
        except PermissionError as exc:
            raise RuntimeError(f"permission denied running command: {command[0]}") from exc
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"command failed: {' '.join(command)}\n{detail}")
        return result


class ReceiveBpfAttachment:
    def __init__(
        self,
        loader_path: Path,
        object_path: Path,
        hook: str = "auto",
        startup_timeout: float = 10.0,
    ):
        if hook not in {"auto", "fentry", "kprobe"}:
            raise RuntimeError(f"unsupported receive hook: {hook}")
        self.loader_path = loader_path
        self.object_path = object_path
        self.hook = hook
        self.startup_timeout = startup_timeout
        self.process: Optional[subprocess.Popen[str]] = None
        self.status: Optional[ReceiveLoaderStatus] = None

    def attach(self) -> ReceiveLoaderStatus:
        if not self.loader_path.exists():
            raise RuntimeError(f"receive BPF loader does not exist: {self.loader_path}")
        if not self.object_path.exists():
            raise RuntimeError(f"receive BPF object does not exist: {self.object_path}")

        command = [
            "sudo",
            "-n",
            str(self.loader_path),
            str(self.object_path),
            self.hook,
        ]
        try:
            self.process = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"required command not found: {command[0]}") from exc
        except PermissionError as exc:
            raise RuntimeError(f"permission denied running: {command[0]}") from exc

        assert self.process.stdout is not None
        ready, _, _ = select.select(
            [self.process.stdout], [], [], self.startup_timeout
        )
        if not ready:
            self.detach()
            raise RuntimeError(
                "receive BPF loader did not report readiness within "
                f"{self.startup_timeout:g}s"
            )

        line = self.process.stdout.readline()
        if not line:
            _, stderr = self.process.communicate()
            detail = stderr.strip() or f"exit status {self.process.returncode}"
            self.process = None
            raise RuntimeError(f"receive BPF attach failed: {detail}")

        try:
            self.status = parse_receive_loader_status(line)
        except RuntimeError:
            self.detach()
            raise
        return self.status

    def detach(self) -> None:
        process = self.process
        self.process = None
        self.status = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


class TcBpfAttachment:
    def __init__(
        self,
        ifname: str,
        object_path: Path,
        section: str,
        pref: int,
        runner: Optional[CommandRunner] = None,
    ):
        self.ifname = ifname
        self.object_path = object_path
        self.section = section
        self.pref = pref
        self.runner = runner or CommandRunner()
        self.attached = False

    def attach(self) -> None:
        if not self.object_path.exists():
            raise RuntimeError(f"BPF object does not exist: {self.object_path}")

        qdisc_result = self.runner.run(
            ["tc", "qdisc", "add", "dev", self.ifname, "clsact"],
            sudo=True,
            check=False,
        )
        qdisc_already_exists = (
            "File exists" in qdisc_result.stderr
            or "Exclusivity flag on" in qdisc_result.stderr
        )
        if qdisc_result.returncode != 0 and not qdisc_already_exists:
            raise RuntimeError(qdisc_result.stderr.strip())

        self.detach(ignore_missing=True)
        self.runner.run(
            [
                "tc",
                "filter",
                "add",
                "dev",
                self.ifname,
                "ingress",
                "protocol",
                "ip",
                "pref",
                str(self.pref),
                "bpf",
                "da",
                "obj",
                str(self.object_path),
                "sec",
                self.section,
            ],
            sudo=True,
        )
        self.attached = True

    def detach(self, ignore_missing: bool = False) -> None:
        result = self.runner.run(
            [
                "tc",
                "filter",
                "del",
                "dev",
                self.ifname,
                "ingress",
                "pref",
                str(self.pref),
            ],
            sudo=True,
            check=False,
        )
        if result.returncode == 0:
            self.attached = False
            return
        if ignore_missing:
            return
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"failed to detach tc filter: {detail}")


class BpftoolMapReader:
    def __init__(
        self,
        program_name: str = UDP_INGRESS_PROGRAM_NAME,
        map_name: str = UDP_INGRESS_MAP_NAME,
        runner: Optional[CommandRunner] = None,
    ):
        self.program_name = program_name
        self.map_name = map_name
        self.runner = runner or CommandRunner()
        self.map_id: Optional[int] = None

    def refresh_map_id(self) -> int:
        programs = self.runner.run_json(["bpftool", "-j", "prog", "show"], sudo=True)
        candidates = [
            program
            for program in programs
            if program.get("name") == self.program_name and program.get("map_ids")
        ]
        if not candidates:
            raise RuntimeError(
                f"could not find loaded BPF program named {self.program_name!r}"
            )

        newest = sorted(candidates, key=lambda item: int(item.get("id", 0)))[-1]
        map_ids = [int(m) for m in (newest.get("map_ids") or [])]

        # Pick the map BY NAME. `map_ids[0]` worked only while the program owned
        # exactly one map; the drop-reason array added a second one and turned this
        # into a coin flip. Losing that flip is SILENT in the worst way: the counters
        # map has a 20-byte key parsed with '<BBHH2xIII', the array key has 4, so the
        # analyzer died on every checkpoint with
        #     error: unexpected udp_key size from bpftool: 4
        # and systemd restarted it 220 times while the kernel counted 126 Mb/s.
        # `self.map_name` already existed and was simply never consulted here.
        #
        # Compare TRUNCATED: the kernel caps map names at BPF_OBJ_NAME_LEN-1 = 15,
        # so 'udp_ingress_counters' reaches userspace as 'udp_ingress_cou'.
        wanted = self.map_name[:15]
        maps = self.runner.run_json(["bpftool", "-j", "map", "show"], sudo=True) or []
        names = {int(m["id"]): str(m.get("name", "")) for m in maps if "id" in m}
        for map_id in map_ids:
            if names.get(map_id, "") == wanted:
                self.map_id = map_id
                return map_id

        raise RuntimeError(
            f"program {self.program_name!r} owns maps "
            f"{[(i, names.get(i, '?')) for i in map_ids]}, none named {wanted!r}"
        )

    def dump_entries(self) -> list[UdpMapEntry]:
        map_id = self.map_id or self.refresh_map_id()
        raw_entries = self.runner.run_json(
            ["bpftool", "-j", "map", "dump", "id", str(map_id)], sudo=True
        )
        if raw_entries is None:
            return []
        return [parse_bpftool_entry(entry) for entry in raw_entries]


class BpftoolDeliveredMapReader:
    def __init__(self, map_id: int, runner: Optional[CommandRunner] = None):
        if map_id <= 0:
            raise RuntimeError(f"invalid delivered map id: {map_id}")
        self.map_id = map_id
        self.runner = runner or CommandRunner()

    def dump_entries(self) -> list[DeliveredMapEntry]:
        raw_entries = self.runner.run_json(
            ["bpftool", "-j", "map", "dump", "id", str(self.map_id)], sudo=True
        )
        if raw_entries is None:
            return []
        return [parse_bpftool_delivered_entry(entry) for entry in raw_entries]


class EbpfIngressCollector:
    def __init__(
        self,
        ifname: Optional[str],
        object_path: Path,
        section: str,
        pref: int,
        bucket_ms: int,
        sample_filter: Optional[SampleFilter] = None,
        attach: bool = True,
        detach_on_close: bool = True,
        process_enricher: Optional[ProcessSocketEnricher] = None,
        delivery_attribution: str = "none",
        receive_object_path: Path = Path("bpf/udp_receive.bpf.o"),
        receive_loader_path: Path = Path("bpf/udp_receive_loader"),
        receive_hook: str = "auto",
        receive_map_id: Optional[int] = None,
    ):
        if delivery_attribution not in {"none", "auto", "cookie", "legacy"}:
            raise RuntimeError(
                f"unsupported delivery attribution: {delivery_attribution}"
            )
        if process_enricher is not None and delivery_attribution == "none":
            delivery_attribution = "legacy"
        if attach:
            self.ifname = ifname or default_route_interface()
        else:
            self.ifname = ifname or "unknown"
        self.bucket_ms = bucket_ms
        self.sample_filter = sample_filter or SampleFilter()
        self.detach_on_close = detach_on_close
        self.process_enricher = process_enricher
        self.requested_delivery_attribution = delivery_attribution
        self.delivery_attribution = delivery_attribution
        self.receive_backend: Optional[str] = None
        self.runner = CommandRunner()
        self.attachment = TcBpfAttachment(
            ifname=self.ifname,
            object_path=object_path,
            section=section,
            pref=pref,
            runner=self.runner,
        )
        self.reader = BpftoolMapReader(runner=self.runner)
        self.previous: dict[tuple[int, int, int, int, int, int, int], UdpMapCounters] = {}
        self.receive_attachment: Optional[ReceiveBpfAttachment] = None
        self.delivered_reader: Optional[BpftoolDeliveredMapReader] = None
        self.delivered_previous: dict[
            tuple[int, int, int, int, int, int, int], UdpMapCounters
        ] = {}

        try:
            if attach:
                self.attachment.attach()
            self.reader.refresh_map_id()
            self._configure_delivery(
                attach=attach,
                receive_object_path=receive_object_path,
                receive_loader_path=receive_loader_path,
                receive_hook=receive_hook,
                receive_map_id=receive_map_id,
            )
        except Exception:
            if self.receive_attachment is not None:
                self.receive_attachment.detach()
            if attach:
                self.attachment.detach(ignore_missing=True)
            raise

    def _configure_delivery(
        self,
        *,
        attach: bool,
        receive_object_path: Path,
        receive_loader_path: Path,
        receive_hook: str,
        receive_map_id: Optional[int],
    ) -> None:
        mode = self.delivery_attribution
        if mode == "none":
            return
        if self.process_enricher is None:
            self.process_enricher = ProcessSocketEnricher()
        if mode == "legacy":
            return

        if not attach:
            if receive_map_id is not None:
                self.delivered_reader = BpftoolDeliveredMapReader(
                    map_id=receive_map_id, runner=self.runner
                )
                self.delivery_attribution = "cookie"
                self.receive_backend = "existing-map"
                return
            if mode == "auto":
                self._fall_back_to_legacy(
                    "--no-attach needs --receive-map-id for socket-cookie "
                    "attribution"
                )
                return
            raise RuntimeError(
                "--delivery-attribution cookie with --no-attach requires "
                "--receive-map-id"
            )

        attachment = ReceiveBpfAttachment(
            loader_path=receive_loader_path,
            object_path=receive_object_path,
            hook=receive_hook,
        )
        try:
            status = attachment.attach()
        except RuntimeError as exc:
            if mode == "auto":
                self._fall_back_to_legacy(str(exc))
                return
            raise

        self.receive_attachment = attachment
        self.delivered_reader = BpftoolDeliveredMapReader(
            map_id=status.map_id, runner=self.runner
        )
        self.delivery_attribution = "cookie"
        self.receive_backend = status.backend

    def _fall_back_to_legacy(self, reason: str) -> None:
        self.delivery_attribution = "legacy"
        self.receive_backend = None
        warnings.warn(
            "receive-side socket-cookie attribution unavailable; using legacy "
            f"port heuristic: {reason}",
            RuntimeWarning,
            stacklevel=3,
        )

    def read_checkpoint(self) -> list[UdpSample]:
        now_ns = time.time_ns()
        bucket_ns = bucket_start_ns(now_ns, self.bucket_ms)
        # MEASURE the interval, don't assume it. The loop is
        #   read_checkpoint() -> emit -> sleep(bucket_ms)
        # and read_checkpoint is NOT free: it shells out to `bpftool map dump` and
        # (with --enrich-processes) scans /proc to map sockets to pids. So the real
        # period is `work + bucket_ms`, which on a busy recorder was ~12 s while we
        # still labelled every sample bucket_ms=1000 — a 12x UNDERSTATEMENT of every
        # rate (25 TV channels reported 12.5 Mb/s instead of ~150 Mb/s).
        # Consumers divide packets/bytes by bucket_ms, so report the elapsed time.
        previous_ns = getattr(self, "_last_checkpoint_ns", None)
        self._last_checkpoint_ns = now_ns
        elapsed_ms = self.bucket_ms
        if previous_ns is not None:
            measured = (now_ns - previous_ns) // 1_000_000
            if measured > 0:
                elapsed_ms = int(measured)

        samples = self._read_ingress(bucket_ns=bucket_ns, elapsed_ms=elapsed_ms)
        if self.delivered_reader is not None:
            samples.extend(
                self._read_delivered(bucket_ns=bucket_ns, elapsed_ms=elapsed_ms)
            )
        return samples

    def _read_ingress(self, bucket_ns: int, elapsed_ms: int) -> list[UdpSample]:
        samples: list[UdpSample] = []

        # AGGREGATE BY IDENTITY FIRST, then diff — never per raw map entry.
        # identity() deliberately ignores the key's padding bytes, so several map
        # entries can share one identity. Diffing per entry made `self.previous`
        # get overwritten by each duplicate in turn, so the "delta" was the
        # difference between two UNRELATED counters — it telescoped to noise
        # (rows of 1-2 packets for a 570 pps channel). Summing first is also
        # simply correct for a PERCPU map read that may split a flow.
        totals: dict[tuple, UdpMapCounters] = {}
        first_entry: dict[tuple, object] = {}
        for entry in self.reader.dump_entries():
            identity = entry.key.identity()
            acc = totals.get(identity)
            totals[identity] = UdpMapCounters(
                packets=(acc.packets if acc else 0) + entry.counters.packets,
                bytes=(acc.bytes if acc else 0) + entry.counters.bytes,
            )
            first_entry.setdefault(identity, entry)

        # a flow that vanished from the map is gone for good (a re-created entry
        # restarts at 0); dropping it keeps `previous` bounded and avoids a bogus
        # negative delta if the same 5-tuple comes back.
        for stale in set(self.previous) - set(totals):
            del self.previous[stale]

        for identity, counters in totals.items():
            entry = first_entry[identity]
            known = identity in self.previous
            previous = self.previous.get(identity, UdpMapCounters(packets=0, bytes=0))
            self.previous[identity] = counters

            # FIRST sight of a flow: only SEED the baseline, never emit.
            # The BPF map counts cumulatively and OUTLIVES this process — the tc
            # program stays attached across a userspace restart. Treating that
            # cumulative total as a delta reported ~10 minutes of traffic as if it
            # happened in one 1000 ms bucket (observed: 348k pps / 3.6 Gb/s for a
            # channel really doing ~570 pps / 6 Mb/s — a ~600x overstatement, once
            # per restart). A rate needs two observations; we have one.
            if not known:
                continue

            packet_delta = counters.packets - previous.packets
            byte_delta = counters.bytes - previous.bytes
            if packet_delta <= 0 and byte_delta <= 0:
                continue

            sample = UdpSample(
                bucket_start_ns=bucket_ns,
                bucket_ms=elapsed_ms,          # MEASURED, not assumed (see above)
                src_ip=entry.key.src_ip,
                dst_ip=entry.key.dst_ip,
                src_port=entry.key.src_port,
                dst_port=entry.key.dst_port,
                ip_proto=entry.key.ip_proto,
                ifindex=entry.key.ifindex,
                ifname=ifname_from_index(entry.key.ifindex, self.ifname),
                packets=max(packet_delta, 0),
                bytes=max(byte_delta, 0),
                layer="ingress",
            )
            enriched_samples = (
                self.process_enricher.enrich(sample)
                if self.delivery_attribution == "legacy"
                and self.process_enricher is not None
                else [sample]
            )
            for enriched_sample in enriched_samples:
                if self.sample_filter.matches(enriched_sample):
                    samples.append(enriched_sample)

        return samples

    def _read_delivered(self, bucket_ns: int, elapsed_ms: int) -> list[UdpSample]:
        if self.delivered_reader is None:
            return []

        totals: dict[tuple, UdpMapCounters] = {}
        first_entry: dict[tuple, DeliveredMapEntry] = {}
        for entry in self.delivered_reader.dump_entries():
            identity = entry.key.identity()
            counters = entry.value.counters
            accumulated = totals.get(identity)
            totals[identity] = UdpMapCounters(
                packets=(accumulated.packets if accumulated else 0)
                + counters.packets,
                bytes=(accumulated.bytes if accumulated else 0) + counters.bytes,
            )
            first_entry.setdefault(identity, entry)

        for stale in set(self.delivered_previous) - set(totals):
            del self.delivered_previous[stale]

        samples: list[UdpSample] = []
        for identity, counters in totals.items():
            entry = first_entry[identity]
            known = identity in self.delivered_previous
            previous = self.delivered_previous.get(
                identity, UdpMapCounters(packets=0, bytes=0)
            )
            self.delivered_previous[identity] = counters
            if not known:
                continue

            packet_delta = counters.packets - previous.packets
            byte_delta = counters.bytes - previous.bytes
            if packet_delta <= 0 and byte_delta <= 0:
                continue

            sample = UdpSample(
                bucket_start_ns=bucket_ns,
                bucket_ms=elapsed_ms,
                src_ip=entry.key.src_ip,
                dst_ip=entry.key.dst_ip,
                src_port=entry.key.src_port,
                dst_port=entry.key.dst_port,
                ip_proto=entry.key.ip_proto,
                ifindex=entry.value.ifindex,
                ifname=ifname_from_index(entry.value.ifindex, self.ifname),
                packets=max(packet_delta, 0),
                bytes=max(byte_delta, 0),
                socket_id=entry.key.socket_cookie,
                layer="delivered",
            )
            enriched_samples = (
                self.process_enricher.enrich_exact(
                    sample,
                    socket_inode=entry.value.socket_inode,
                    socket_cookie=entry.key.socket_cookie,
                )
                if self.process_enricher is not None
                else [sample]
            )
            for enriched_sample in enriched_samples:
                if self.sample_filter.matches(enriched_sample):
                    samples.append(enriched_sample)
        return samples

    def close(self) -> None:
        if self.detach_on_close:
            if self.receive_attachment is not None:
                self.receive_attachment.detach()
            self.attachment.detach(ignore_missing=True)


def parse_bpftool_entry(entry: dict[str, Any]) -> UdpMapEntry:
    key = parse_bpftool_key(entry.get("key"))
    value = entry.get("value")
    values = entry.get("values")
    counters = parse_bpftool_counters(value=value, values=values)
    return UdpMapEntry(key=key, counters=counters)


def parse_bpftool_key(raw_key: Any) -> UdpMapKey:
    if isinstance(raw_key, dict):
        return UdpMapKey(
            family=int(raw_key["family"]),
            ip_proto=int(raw_key["ip_proto"]),
            src_port=int(raw_key["src_port"]),
            dst_port=int(raw_key["dst_port"]),
            ifindex=int(raw_key["ifindex"]),
            src_ip4=int(raw_key["src_ip4"]),
            dst_ip4=int(raw_key["dst_ip4"]),
        )

    key_bytes = raw_bytes(raw_key)
    if len(key_bytes) < 20:
        raise RuntimeError(f"unexpected udp_key size from bpftool: {len(key_bytes)}")

    family, ip_proto, src_port, dst_port, ifindex, src_ip4, dst_ip4 = struct.unpack(
        "<BBHH2xIII", key_bytes[:20]
    )
    return UdpMapKey(
        family=family,
        ip_proto=ip_proto,
        src_port=src_port,
        dst_port=dst_port,
        ifindex=ifindex,
        src_ip4=src_ip4,
        dst_ip4=dst_ip4,
    )


def parse_bpftool_counters(value: Any, values: Any) -> UdpMapCounters:
    if values is not None:
        packets = 0
        bytes_seen = 0
        for cpu_value in values:
            parsed = parse_bpftool_counters(value=cpu_value.get("value"), values=None)
            packets += parsed.packets
            bytes_seen += parsed.bytes
        return UdpMapCounters(packets=packets, bytes=bytes_seen)

    if isinstance(value, dict):
        return UdpMapCounters(packets=int(value["packets"]), bytes=int(value["bytes"]))

    value_bytes = raw_bytes(value)
    if len(value_bytes) < 16:
        raise RuntimeError(
            f"unexpected udp_counters size from bpftool: {len(value_bytes)}"
        )
    packets, bytes_seen = struct.unpack("<QQ", value_bytes[:16])
    return UdpMapCounters(packets=packets, bytes=bytes_seen)


def parse_bpftool_delivered_entry(entry: dict[str, Any]) -> DeliveredMapEntry:
    key = parse_bpftool_delivered_key(entry.get("key"))
    value = parse_bpftool_delivered_value(
        value=entry.get("value"), values=entry.get("values")
    )
    return DeliveredMapEntry(key=key, value=value)


def parse_bpftool_delivered_key(raw_key: Any) -> DeliveredMapKey:
    if isinstance(raw_key, dict):
        return DeliveredMapKey(
            socket_cookie=int(raw_key["socket_cookie"]),
            src_ip4=int(raw_key["src_ip4"]),
            dst_ip4=int(raw_key["dst_ip4"]),
            src_port=int(raw_key["src_port"]),
            dst_port=int(raw_key["dst_port"]),
            family=int(raw_key["family"]),
            ip_proto=int(raw_key["ip_proto"]),
        )

    key_bytes = raw_bytes(raw_key)
    if len(key_bytes) < 24:
        raise RuntimeError(
            f"unexpected delivered_key size from bpftool: {len(key_bytes)}"
        )
    socket_cookie, src_ip4, dst_ip4, src_port, dst_port, family, ip_proto = (
        struct.unpack("<QIIHHBB2x", key_bytes[:24])
    )
    return DeliveredMapKey(
        socket_cookie=socket_cookie,
        src_ip4=src_ip4,
        dst_ip4=dst_ip4,
        src_port=src_port,
        dst_port=dst_port,
        family=family,
        ip_proto=ip_proto,
    )


def parse_bpftool_delivered_value(value: Any, values: Any) -> DeliveredMapValue:
    if values is not None:
        packets = 0
        bytes_seen = 0
        socket_inode = 0
        ifindex = 0
        for cpu_value in values:
            parsed = parse_bpftool_delivered_value(
                value=cpu_value.get("value"), values=None
            )
            packets += parsed.packets
            bytes_seen += parsed.bytes
            socket_inode = socket_inode or parsed.socket_inode
            ifindex = ifindex or parsed.ifindex
        return DeliveredMapValue(
            packets=packets,
            bytes=bytes_seen,
            socket_inode=socket_inode,
            ifindex=ifindex,
        )

    if isinstance(value, dict):
        return DeliveredMapValue(
            packets=int(value["packets"]),
            bytes=int(value["bytes"]),
            socket_inode=int(value.get("socket_inode", 0)),
            ifindex=int(value.get("ifindex", 0)),
        )

    value_bytes = raw_bytes(value)
    if len(value_bytes) < 32:
        raise RuntimeError(
            f"unexpected delivered_value size from bpftool: {len(value_bytes)}"
        )
    packets, bytes_seen, socket_inode, ifindex = struct.unpack(
        "<QQQI4x", value_bytes[:32]
    )
    return DeliveredMapValue(
        packets=packets,
        bytes=bytes_seen,
        socket_inode=socket_inode,
        ifindex=ifindex,
    )


def raw_bytes(value: Any) -> bytes:
    if not isinstance(value, list):
        raise RuntimeError(f"expected bpftool byte list, got: {value!r}")
    return bytes(int(part, 16) if isinstance(part, str) else int(part) for part in value)


def ipv4_from_bpf_int(value: int) -> str:
    return str(ipaddress.IPv4Address(struct.pack("<I", value)))


def ifname_from_index(ifindex: int, fallback: str) -> str:
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return fallback


def default_route_interface() -> str:
    result = CommandRunner().run(["ip", "route", "show", "default"], check=False)
    if result.returncode == 0:
        words = result.stdout.split()
        if "dev" in words:
            dev_index = words.index("dev") + 1
            if dev_index < len(words):
                return words[dev_index]

    env_ifname = os.environ.get("UDP_ANALYZER_IFACE")
    if env_ifname:
        return env_ifname

    raise RuntimeError(
        "could not detect default interface; pass --interface or set "
        "UDP_ANALYZER_IFACE"
    )
