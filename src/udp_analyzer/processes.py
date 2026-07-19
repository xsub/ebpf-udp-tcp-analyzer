from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Optional

from .models import UdpSample


CONTAINER_ID_RE = re.compile(r"([0-9a-f]{64})")


@dataclass(frozen=True)
class ProcessSocket:
    host_pid: int
    container_pid: int
    process_name: str
    command_line: str
    netns_id: int
    container_id: str
    socket_inode: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int


class ProcessSocketInventory:
    def __init__(self, proc_root: Path = Path("/proc")):
        self.proc_root = proc_root

    def scan(self, process_name: Optional[str] = None) -> list[ProcessSocket]:
        sockets: list[ProcessSocket] = []
        for pid in self.iter_pids():
            name = read_text(self.proc_root / str(pid) / "comm").strip()
            if process_name and name != process_name:
                continue

            socket_inodes = self.process_socket_inodes(pid)
            if not socket_inodes:
                continue

            command_line = read_cmdline(self.proc_root / str(pid) / "cmdline")
            container_id = read_container_id(self.proc_root / str(pid) / "cgroup")
            container_pid = read_container_pid(self.proc_root / str(pid) / "status", pid)
            netns_id = read_namespace_id(self.proc_root / str(pid) / "ns" / "net")

            for socket_row in self.read_udp_sockets(pid):
                if socket_row.socket_inode not in socket_inodes:
                    continue
                sockets.append(
                    ProcessSocket(
                        host_pid=pid,
                        container_pid=container_pid,
                        process_name=name,
                        command_line=command_line,
                        netns_id=netns_id,
                        container_id=container_id,
                        socket_inode=socket_row.socket_inode,
                        local_ip=socket_row.local_ip,
                        local_port=socket_row.local_port,
                        remote_ip=socket_row.remote_ip,
                        remote_port=socket_row.remote_port,
                    )
                )
        return sockets

    def iter_pids(self) -> Iterable[int]:
        for child in self.proc_root.iterdir():
            if child.name.isdigit():
                yield int(child.name)

    def process_socket_inodes(self, pid: int) -> set[int]:
        fd_dir = self.proc_root / str(pid) / "fd"
        inodes: set[int] = set()
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            return inodes

        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                try:
                    inodes.add(int(target[len("socket:[") : -1]))
                except ValueError:
                    continue
        return inodes

    def read_udp_sockets(self, pid: int) -> list["UdpSocketRow"]:
        rows = []
        for name in ("udp", "udp6"):
            path = self.proc_root / str(pid) / "net" / name
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            rows.extend(parse_proc_net_udp(text))
        return rows


class ProcessSocketEnricher:
    def __init__(
        self,
        process_name: Optional[str] = None,
        proc_root: Path = Path("/proc"),
        cache_ttl: float = 1.0,
    ):
        self.process_name = process_name
        self.inventory = ProcessSocketInventory(proc_root=proc_root)
        self.cache_ttl = cache_ttl
        self.cache_at = 0.0
        self.cached_sockets: list[ProcessSocket] = []

    def enrich(self, sample: UdpSample) -> list[UdpSample]:
        """Legacy best-effort enrichment by local address and port."""
        matches = self.find_matches(sample)
        if not matches:
            return [sample]

        enriched = [sample]
        for match in matches:
            enriched.append(
                replace(
                    sample,
                    layer="delivered",
                    netns_id=match.netns_id,
                    container_id=match.container_id,
                    process_name=match.process_name,
                    host_pid=match.host_pid,
                    container_pid=match.container_pid,
                    socket_id=match.socket_inode,
                )
            )
        return enriched

    def enrich_exact(
        self, sample: UdpSample, socket_inode: int, socket_cookie: int
    ) -> list[UdpSample]:
        """Enrich a kernel-attributed row without repeating port correlation."""
        attributed = replace(sample, layer="delivered", socket_id=socket_cookie)
        matches = self.find_inode_matches(socket_inode)
        if not matches:
            return [attributed]

        return [
            replace(
                attributed,
                netns_id=match.netns_id,
                container_id=match.container_id,
                process_name=match.process_name,
                host_pid=match.host_pid,
                container_pid=match.container_pid,
            )
            for match in matches
        ]

    def find_matches(self, sample: UdpSample) -> list[ProcessSocket]:
        sockets = self.sockets()
        return [
            socket_row
            for socket_row in sockets
            if socket_row.local_port == sample.dst_port
            and (socket_row.local_ip in {"0.0.0.0", sample.dst_ip})
        ]

    def find_inode_matches(self, socket_inode: int) -> list[ProcessSocket]:
        if not socket_inode:
            return []
        return [
            socket_row
            for socket_row in self.sockets()
            if socket_row.socket_inode == socket_inode
        ]

    def sockets(self) -> list[ProcessSocket]:
        now = time.monotonic()
        if now - self.cache_at > self.cache_ttl:
            self.cached_sockets = self.inventory.scan(process_name=self.process_name)
            self.cache_at = now
        return self.cached_sockets


@dataclass(frozen=True)
class UdpSocketRow:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    socket_inode: int


def parse_proc_net_udp(text: str) -> list[UdpSocketRow]:
    rows = []
    for line in text.splitlines()[1:]:
        columns = line.split()
        if len(columns) < 10:
            continue
        local_ip, local_port = parse_proc_address(columns[1])
        remote_ip, remote_port = parse_proc_address(columns[2])
        rows.append(
            UdpSocketRow(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                socket_inode=int(columns[9]),
            )
        )
    return rows


def parse_proc_address(value: str) -> tuple[str, int]:
    raw_ip, raw_port = value.split(":", 1)
    port = int(raw_port, 16)
    if len(raw_ip) == 8:
        ip_bytes = bytes.fromhex(raw_ip)[::-1]
        ip = ".".join(str(part) for part in ip_bytes)
        return ip, port
    if len(raw_ip) == 32:
        chunks = [raw_ip[index : index + 8] for index in range(0, 32, 8)]
        ip = ":".join(chunk for chunk in chunks)
        return ip, port
    return raw_ip, port


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def read_cmdline(path: Path) -> str:
    data = read_text(path)
    return " ".join(part for part in data.split("\x00") if part)


def read_container_id(path: Path) -> str:
    text = read_text(path)
    match = CONTAINER_ID_RE.search(text)
    return match.group(1) if match else ""


def read_container_pid(path: Path, fallback: int) -> int:
    for line in read_text(path).splitlines():
        if line.startswith("NSpid:"):
            parts = line.split()
            try:
                return int(parts[-1])
            except (IndexError, ValueError):
                return fallback
    return fallback


def read_namespace_id(path: Path) -> int:
    try:
        target = os.readlink(path)
    except OSError:
        return 0
    if target.startswith("net:[") and target.endswith("]"):
        try:
            return int(target[len("net:[") : -1])
        except ValueError:
            return 0
    return 0
