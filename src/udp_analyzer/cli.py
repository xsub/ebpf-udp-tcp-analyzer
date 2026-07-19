from __future__ import annotations

import argparse
import signal
import time
from pathlib import Path
from typing import Optional, Union

from .collectors import DryRunCollector, EbpfCollector
from .models import SampleFilter
from .output import emit_samples
from .processes import ProcessSocketEnricher
from .writers import (
    ClickHouseHttpWriter,
    DuckDBWriter,
    NullWriter,
    ParquetWriter,
    SQLiteWriter,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="udp-analyzer",
        description="Universal UDP traffic analyzer with checkpointed storage.",
    )
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser("run", help="run the analyzer")
    run.add_argument("--collector", choices=["dry-run", "ebpf"], default="dry-run")
    run.add_argument("--bucket-ms", type=int, default=1000)
    run.add_argument("--watch", action="store_true", help="keep polling checkpoints")
    run.add_argument(
        "--duration",
        type=float,
        default=None,
        help="stop after N seconds; implies --watch",
    )
    run.add_argument("--output", choices=["table", "json", "none"], default="table")
    run.add_argument(
        "--storage",
        choices=["none", "sqlite", "duckdb", "parquet", "clickhouse"],
        default="none",
    )
    run.add_argument("--db-path", default="data/udp_analyzer.sqlite")
    run.add_argument("--clickhouse-url", default="http://localhost:8123")
    run.add_argument("--clickhouse-table", default="udp_samples")
    run.add_argument(
        "--interface",
        help="interface to attach the eBPF ingress program to; defaults to route dev",
    )
    run.add_argument("--bpf-object", default="bpf/udp_ingress.bpf.o")
    run.add_argument("--bpf-section", default="classifier/udp_ingress")
    run.add_argument("--tc-pref", type=int, default=49152)
    run.add_argument(
        "--delivery-attribution",
        choices=["auto", "cookie", "legacy", "none"],
        default=None,
        help=(
            "delivered-row backend: auto prefers socket cookies and falls back "
            "to the legacy port heuristic"
        ),
    )
    run.add_argument("--receive-bpf-object", default="bpf/udp_receive.bpf.o")
    run.add_argument("--receive-loader", default="bpf/udp_receive_loader")
    run.add_argument(
        "--receive-hook",
        choices=["auto", "fentry", "kprobe"],
        default="auto",
        help="receive hook selection; auto prefers fentry and falls back to kprobe",
    )
    run.add_argument(
        "--receive-map-id",
        type=int,
        help="existing delivered map ID to read together with --no-attach",
    )
    run.add_argument(
        "--no-attach",
        action="store_true",
        help="read an already loaded eBPF map instead of attaching tc filter",
    )
    run.add_argument(
        "--keep-attached",
        action="store_true",
        help="leave tc filter attached when the analyzer exits",
    )
    run.add_argument(
        "--enrich-processes",
        action="store_true",
        help=(
            "add delivered rows; prefers receive-side socket cookies and falls "
            "back to the legacy /proc port heuristic"
        ),
    )
    run.add_argument("--src-ip")
    run.add_argument("--dst-ip")
    run.add_argument("--src-port", type=int)
    run.add_argument("--dst-port", type=int)
    run.add_argument("--ifname")
    run.add_argument("--process-name")
    run.add_argument("--layer", choices=["ingress", "delivered"])
    run.set_defaults(func=run_analyzer)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        parser.exit(1, f"udp-analyzer: error: {exc}\n")


def run_analyzer(args: argparse.Namespace) -> None:
    sample_filter = SampleFilter(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        ifname=args.ifname,
        process_name=args.process_name,
        layer=args.layer,
    )
    collector = create_collector(args, sample_filter)
    writer = create_writer(args)
    watch = args.watch or args.duration is not None
    deadline = time.monotonic() + args.duration if args.duration is not None else None

    # Run under systemd, `systemctl stop` sends SIGTERM, whose DEFAULT action kills
    # the process outright — `finally` never runs, so collector.close() never detaches
    # the tc filter. The BPF program then stays attached to the interface with nobody
    # reading it: it keeps running on every packet, and its map survives (we found one
    # orphaned and saturated at 65536/65536 long after the service was 'inactive').
    # Translating the signal into a normal exception lets the `finally` clean up.
    stopping = False

    def _on_signal(signum, _frame):
        nonlocal stopping
        stopping = True
        raise KeyboardInterrupt(f"signal {signum}")

    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, _on_signal)
        except (ValueError, OSError):
            pass                     # not the main thread / unsupported — best effort

    try:
        while True:
            samples = collector.read_checkpoint()
            emit_samples(samples, args.output)
            writer.write_samples(samples)

            if not watch or stopping:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(args.bucket_ms / 1000)
    except KeyboardInterrupt:
        pass                         # clean shutdown: fall through to `finally`
    finally:
        collector.close()            # detaches the tc filter (detach_on_close)
        writer.flush()
        writer.close()


def create_collector(
    args: argparse.Namespace, sample_filter: SampleFilter
) -> Union[DryRunCollector, EbpfCollector]:
    collector_name = args.collector
    bucket_ms = args.bucket_ms
    if bucket_ms <= 0:
        raise RuntimeError("--bucket-ms must be greater than zero")
    if collector_name == "dry-run":
        return DryRunCollector(bucket_ms=bucket_ms, sample_filter=sample_filter)
    if collector_name == "ebpf":
        delivery_attribution = args.delivery_attribution
        if delivery_attribution is None:
            delivery_attribution = (
                "auto" if args.enrich_processes or args.process_name else "none"
            )
        if delivery_attribution == "none" and (
            args.enrich_processes or args.process_name
        ):
            raise RuntimeError(
                "--enrich-processes/--process-name cannot be combined with "
                "--delivery-attribution none"
            )
        process_enricher = None
        if delivery_attribution != "none":
            process_enricher = ProcessSocketEnricher(process_name=args.process_name)
        return EbpfCollector(
            bucket_ms=bucket_ms,
            sample_filter=sample_filter,
            ifname=args.interface,
            object_path=Path(args.bpf_object),
            section=args.bpf_section,
            pref=args.tc_pref,
            attach=not args.no_attach,
            detach_on_close=not args.keep_attached,
            process_enricher=process_enricher,
            delivery_attribution=delivery_attribution,
            receive_object_path=Path(args.receive_bpf_object),
            receive_loader_path=Path(args.receive_loader),
            receive_hook=args.receive_hook,
            receive_map_id=args.receive_map_id,
        )
    raise RuntimeError(f"unsupported collector: {collector_name}")


def create_writer(args: argparse.Namespace):
    if args.storage == "none":
        return NullWriter()
    if args.storage == "sqlite":
        return SQLiteWriter(Path(args.db_path))
    if args.storage == "duckdb":
        return DuckDBWriter(Path(args.db_path))
    if args.storage == "parquet":
        return ParquetWriter(Path(args.db_path))
    if args.storage == "clickhouse":
        return ClickHouseHttpWriter(args.clickhouse_url, args.clickhouse_table)
    raise RuntimeError(f"unsupported storage: {args.storage}")
