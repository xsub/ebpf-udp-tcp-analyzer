from __future__ import annotations

import re
import shlex
import socket
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SYSTEMD_UNIT_SUFFIXES = (".service",)
DEFAULT_USER_UNIT_DIRS = (
    Path("~/.config/systemd/user").expanduser(),
    Path("/etc/systemd/user"),
    Path("/usr/lib/systemd/user"),
)


@dataclass(frozen=True)
class ChannelTarget:
    channel: str
    unit: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    addresses: tuple[str, ...] = ()

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class ChannelMatch:
    target: Optional[ChannelTarget]
    status: str


class ChannelCatalog:
    def __init__(self, targets: Iterable[ChannelTarget]):
        self.targets = tuple(targets)
        self.by_unit = {target.unit: target for target in self.targets}

    @classmethod
    def from_unit_paths(cls, paths: Iterable[Path]) -> "ChannelCatalog":
        return cls(load_channel_targets(paths))

    def match(self, unit: str, dst_ip: str, dst_port: int) -> ChannelMatch:
        target = self.by_unit.get(unit)
        if target is None:
            return ChannelMatch(target=None, status="unknown_unit")
        if target.port != dst_port:
            return ChannelMatch(target=target, status="unexpected_flow")
        if target.addresses and dst_ip not in set(target.addresses):
            return ChannelMatch(target=target, status="unexpected_flow")
        return ChannelMatch(target=target, status="matched")

    def resolve(
        self,
        resolver: Optional[
            Callable[[str, int], Iterable[tuple[int, int, int, str, tuple]]]
        ] = None,
    ) -> "ChannelCatalog":
        resolver = resolver or socket.getaddrinfo
        return ChannelCatalog(resolve_channel_targets(self.targets, resolver=resolver))


def default_user_unit_paths(
    unit_dirs: Iterable[Path] = DEFAULT_USER_UNIT_DIRS,
) -> list[Path]:
    paths: list[Path] = []
    for directory in unit_dirs:
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for child in children:
            if child.name.endswith(SYSTEMD_UNIT_SUFFIXES):
                paths.append(child)
    return sorted(paths)


def load_channel_targets(paths: Iterable[Path]) -> list[ChannelTarget]:
    targets = []
    for path in paths:
        unit = path.name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        urls = sorted(set(extract_urls_from_unit(text)))
        if not urls:
            continue
        if len(urls) > 1:
            raise RuntimeError(
                f"{unit} contains {len(urls)} URLs; expected one URL per unit"
            )
        targets.append(channel_target_from_url(unit=unit, url=urls[0]))
    return targets


def extract_urls_from_unit(text: str) -> list[str]:
    text = join_systemd_continuations(text)
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("Environment="):
            urls.extend(extract_urls_from_environment(line[len("Environment=") :]))
            continue
        urls.extend(URL_RE.findall(line))
    return [cleanup_url(url) for url in urls]


def extract_urls_from_environment(value: str) -> list[str]:
    try:
        parts = shlex.split(value, comments=False, posix=True)
    except ValueError:
        parts = value.split()
    urls = []
    for part in parts:
        candidate = part.split("=", 1)[-1]
        urls.extend(URL_RE.findall(candidate))
    return urls


def join_systemd_continuations(text: str) -> str:
    lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    return "\n".join(lines)


def cleanup_url(url: str) -> str:
    return url.rstrip("),;]")


def channel_target_from_url(unit: str, url: str) -> ChannelTarget:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(f"{unit} URL must use http or https: {url}")
    if not parsed.hostname:
        raise RuntimeError(f"{unit} URL has no host: {url}")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return ChannelTarget(
        channel=unit.removesuffix(".service"),
        unit=unit,
        url=url,
        scheme=parsed.scheme,
        host=parsed.hostname.lower(),
        port=port,
        path=path,
    )


def resolve_channel_targets(
    targets: Iterable[ChannelTarget],
    resolver: Callable[[str, int], Iterable[tuple[int, int, int, str, tuple]]],
) -> list[ChannelTarget]:
    resolved = []
    for target in targets:
        addresses = []
        try:
            rows = resolver(target.host, target.port)
        except OSError:
            rows = []
        for family, _socktype, _proto, _canonname, sockaddr in rows:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            if not sockaddr:
                continue
            addresses.append(str(sockaddr[0]))
        resolved.append(replace(target, addresses=tuple(sorted(set(addresses)))))
    return resolved
