from __future__ import annotations

import json
import sys
from typing import Any, Optional, TextIO

TABLE_COLUMNS = [
    "ts",
    "layer",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "ifname",
    "process_name",
    "host_pid",
    "packets",
    "bytes",
]

CHANNEL_TABLE_COLUMNS = [
    "ts",
    "layer",
    "channel",
    "unit",
    "host",
    "dst_ip",
    "dst_port",
    "tx_bytes",
    "rx_bytes",
    "connections",
    "status",
]


def emit_samples(
    samples: list[Any], output: str, stream: Optional[TextIO] = None
) -> None:
    stream = stream or sys.stdout
    if output == "none":
        return
    if output == "json":
        for sample in samples:
            print(json.dumps(sample.to_dict(), sort_keys=True), file=stream)
        return
    if output == "table":
        _emit_table(samples, stream)
        return
    raise ValueError(f"unsupported output mode: {output}")


def _emit_table(samples: list[Any], stream: TextIO) -> None:
    if not samples:
        print("(no samples)", file=stream)
        return

    columns = _table_columns(samples)
    rows = []
    for sample in samples:
        data = sample.to_dict()
        rows.append([str(data.get(column, "")) for column in columns])

    widths = [
        max(len(column), *(len(row[index]) for row in rows))
        for index, column in enumerate(columns)
    ]
    header = "  ".join(
        column.ljust(widths[index]) for index, column in enumerate(columns)
    )
    print(header, file=stream)
    print("  ".join("-" * width for width in widths), file=stream)
    for row in rows:
        print(
            "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)),
            file=stream,
        )


def _table_columns(samples: list[Any]) -> list[str]:
    for sample in samples:
        data = sample.to_dict()
        if data.get("layer") == "tcp_channel":
            return CHANNEL_TABLE_COLUMNS
    return TABLE_COLUMNS
