from __future__ import annotations

import re
import shlex
import socket
import warnings
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse


URL_RE = re.compile(r"(?:https?|udp|rtp)://[^\s\"'<>]+")
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
        joined = join_systemd_continuations(text)
        # Template units (name@.service) keep the URL OUTSIDE the unit file:
        # ExecStart says ${INPUT_URL} and EnvironmentFile=<dir>/%i.env points at
        # one env file per instance. That is the recorder deployment contract
        # (one instance = one channel = one URL), so enumerate the instances by
        # expanding %i in the EnvironmentFile pattern instead of skipping the
        # template as "no URL in file".
        if unit.endswith("@.service"):
            targets.extend(template_instance_targets(path, joined))
            continue
        urls = set(extract_urls_from_unit(text))
        for env_path in environment_file_paths(joined, unit_path=path):
            urls.update(urls_from_env_file(env_path))
        urls = sorted(urls)
        if not urls:
            continue
        if len(urls) > 1:
            # A foreign unit with several URLs (Documentation= plus ExecStart=…)
            # must not take the whole monitor down — it is not even a channel.
            # Warn and skip; a real channel unit has exactly one URL.
            warnings.warn(
                f"{unit} contains {len(urls)} URLs; expected one URL per unit — skipping",
                RuntimeWarning, stacklevel=2,
            )
            continue
        targets.append(channel_target_from_url(unit=unit, url=urls[0]))
    return targets


def environment_file_paths(joined_text: str, unit_path: Path) -> list[Path]:
    """EnvironmentFile= paths of a unit, with systemd's `-` prefix (optional
    file) stripped and %h expanded. Only non-template paths (no %i)."""
    out = []
    for line in joined_text.splitlines():
        line = line.strip()
        if not line.startswith("EnvironmentFile="):
            continue
        spec = line[len("EnvironmentFile="):].strip().lstrip("-")
        if not spec or "%i" in spec:
            continue
        out.append(Path(expand_home_specifier(spec, unit_path)))
    return out


def expand_home_specifier(spec: str, unit_path: Path) -> str:
    """Expand systemd's %h. The catalog often runs as root scanning ANOTHER
    user's unit dir, so `Path.home()` would lie; when the unit lives under
    <home>/.config/systemd/user, that home is the honest expansion."""
    if "%h" not in spec:
        return spec
    # No resolve(): symlinked mounts (macOS /home firmlink in tests, bind
    # mounts in prod) would rewrite the honest textual prefix.
    text = str(unit_path.parent)
    idx = text.find(".config/systemd/user")
    home = text[: idx - 1] if idx > 0 else str(Path.home())
    return spec.replace("%h", home)


def urls_from_env_file(env_path: Path) -> list[str]:
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return []
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        urls.extend(URL_RE.findall(line.split("=", 1)[1]))
    return [cleanup_url(u) for u in urls]


def template_instance_targets(template_path: Path, joined_text: str) -> list[ChannelTarget]:
    """One ChannelTarget per template instance, discovered by expanding %i in
    the template's EnvironmentFile pattern (e.g. /etc/ffmpeg-rec/%i.env)."""
    prefix = template_path.name[: -len("@.service")]
    targets: list[ChannelTarget] = []
    for line in joined_text.splitlines():
        line = line.strip()
        if not line.startswith("EnvironmentFile="):
            continue
        spec = line[len("EnvironmentFile="):].strip().lstrip("-")
        if "%i" not in spec:
            continue
        spec_path = Path(expand_home_specifier(spec, template_path))
        # %i supported in the FILENAME component only (the recorder contract:
        # <env_dir>/%i.env); %i in a directory name is out of scope.
        if "%i" not in spec_path.name or "%i" in str(spec_path.parent):
            continue
        fhead, _, ftail = spec_path.name.partition("%i")
        for env_path in sorted(spec_path.parent.glob(f"{fhead}*{ftail}")):
            name = env_path.name
            if not (name.startswith(fhead) and name.endswith(ftail)):
                continue
            instance = name[len(fhead): len(name) - len(ftail)] if ftail else name[len(fhead):]
            if not instance:
                continue
            urls = sorted(set(urls_from_env_file(env_path)))
            if len(urls) != 1:
                if len(urls) > 1:
                    warnings.warn(
                        f"{env_path} contains {len(urls)} URLs; expected one — skipping",
                        RuntimeWarning, stacklevel=2,
                    )
                continue
            unit = f"{prefix}@{instance}.service"
            target = channel_target_from_url(unit=unit, url=urls[0])
            # channel = the instance, not "ffmpeg@instance": the instance IS the
            # channel name in the recorder contract.
            targets.append(replace(target, channel=instance))
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
    if parsed.scheme not in {"http", "https", "udp", "rtp"}:
        raise RuntimeError(f"{unit} URL must use http, https, udp or rtp: {url}")
    if not parsed.hostname:
        raise RuntimeError(f"{unit} URL has no host: {url}")
    port = parsed.port
    if port is None:
        # UDP/RTP (multicast) nie ma sensownego portu domyslnego — inaczej niz HTTP.
        if parsed.scheme in {"udp", "rtp"}:
            raise RuntimeError(f"{unit} UDP/RTP URL needs explicit port: {url}")
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
