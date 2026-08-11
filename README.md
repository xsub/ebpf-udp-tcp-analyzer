# ebpf-udp-tcp-analyzer

(previously `ebpf-udp-analyzer` — GitHub redirects the old URL)

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![eBPF](https://img.shields.io/badge/eBPF-enabled-orange)
![Linux](https://img.shields.io/badge/platform-linux-green)

Universal eBPF UDP **and TCP** traffic analyzer with Python user space,
checkpointed storage, and a Docker/ffmpeg vertical harness. UDP flows are
measured on the wire (tc ingress + optional receive-side socket attribution);
TCP channels are attributed per systemd unit (one unit = one channel = one URL).

## What It Does

The UDP side monitors incoming IPv4 UDP traffic on a Linux interface.
The eBPF program runs at `tc ingress` and updates in-kernel counters keyed by:

- source IP
- destination IP
- source UDP port
- destination UDP port
- receiving interface

The Python user-space collector periodically reads those counters, converts
absolute eBPF map values into checkpoint deltas, optionally enriches rows with
`/proc` socket/process metadata, and writes the result as JSON, tables, or
storage rows.

Example ingress row:

```json
{"src_ip": "203.0.113.53", "src_port": 53, "dst_ip": "198.51.100.20", "dst_port": 58417, "ifname": "eth0", "packets": 1, "bytes": 61, "layer": "ingress"}
```

With process enrichment enabled, matching UDP sockets can also produce delivered
rows such as:

```json
{"process_name": "ffmpeg", "host_pid": 4242, "socket_id": 869157, "layer": "delivered"}
```

Current delivered rows are a best-effort `/proc` enrichment: the collector
matches ingress UDP samples to sockets by local destination port and local
address. This is useful for simple one-socket-per-port workloads, but it is a
heuristic until receive-side socket-cookie attribution is enabled. It cannot
prove that the kernel delivered a specific packet to a specific socket when
multiple sockets share a port, when multicast fanout is involved, or when socket
state changes between packet capture and `/proc` scanning.

The next attribution target is a receive-side delivered map keyed by socket
cookie plus the UDP 5-tuple. The preferred attach point is `fentry` on a UDP
receive-path function that has both the selected `struct sock *` and packet
context; `kprobe` is the compatibility fallback. The existing port-based
enrichment will remain available as a legacy/fallback mode for kernels where the
receive-side hook is unavailable.

The project is intentionally split into:

- eBPF hot path: collect UDP counters in kernel maps
- Python checkpoint daemon: drain counters, enrich metadata, write batches
- storage backends: local and networked history for later Python analysis
- harness: reproducible Dockerized ffmpeg workload

## TCP Channel Attribution

The TCP side (mainline since the tcp-attribution-v2 merge) attributes outbound
TCP traffic produced by
systemd user units where the deployment contract is:

```text
one systemd user unit = one channel = one configured URL
```

The analyzer does not try to decrypt HTTPS or infer URL paths from TCP. Instead,
it treats the systemd unit configuration as the source of HTTP semantics and
uses eBPF only for measured TCP socket traffic:

```text
systemd user unit -> configured URL / host / port
eBPF TCP hooks    -> socket cookie / pid / cgroup / dst_ip:port / tx-rx bytes
Python            -> pid -> unit -> channel URL attribution
```

This remains deterministic even when many channels use the same `host:443`,
because the channel boundary is the unit, not the remote endpoint. If a unit
connects to an IP or port outside its configured URL, rows are emitted with
`status=unexpected_flow`.

Run a local dry-run:

```sh
PYTHONPATH=src python3 -m udp_analyzer run-channels \
  --collector dry-run \
  --unit-file ~/.config/systemd/user/channel-a.service
```

Build the TCP channel eBPF object and loader on Linux:

```sh
make -C bpf tcp-channel
```

Run the real TCP collector:

```sh
PYTHONPATH=src python3 -m udp_analyzer run-channels \
  --collector ebpf \
  --watch \
  --unit-dir ~/.config/systemd/user
```

Deployment note: for a long-running monitor, run `run-channels` from a systemd
unit with `--output json` appended (`>>`) to an NDJSON file — TCP rows may share
the file with the UDP monitor's rows (consumers dispatch on `layer`). Validated
against ground truth on a production radio recorder (46 HTTP streams, 15 min:
96.6% `matched`, 128.2 kbps per channel vs 133.5 kbps on disk after transcode).

Example row:

```json
{"channel":"channel-a","unit":"channel-a.service","url":"https://api.example.com/foo","host":"api.example.com","dst_ip":"203.0.113.10","dst_port":443,"tx_bytes":1201,"rx_bytes":64001,"connections":1,"status":"matched","layer":"tcp_channel"}
```

## Text Screenshots

Dry-run table output:

```text
$ PYTHONPATH=src python3 -m udp_analyzer run --output table
ts                        layer      src_ip      src_port  dst_ip         dst_port  ifname  process_name  host_pid  packets  bytes
------------------------  ---------  ----------  --------  -------------  --------  ------  ------------  --------  -------  ------
2026-07-06T22:51:31.000Z  delivered  192.0.2.10  40000     198.51.100.20  5000      eth0    ffmpeg        4242      101      132916
2026-07-06T22:51:31.000Z  delivered  192.0.2.11  40010     198.51.100.20  5001      eth0    ffmpeg        4243      77       92400
2026-07-06T22:51:31.000Z  ingress    192.0.2.12  40020     198.51.100.20  5999      eth0                  0         15       7680
```

Filtered JSON output:

```text
$ PYTHONPATH=src python3 -m udp_analyzer run --output json --process-name ffmpeg --layer delivered
{"bytes": 132916, "dst_ip": "198.51.100.20", "dst_port": 5000, "ifname": "eth0", "layer": "delivered", "packets": 101, "process_name": "ffmpeg", "src_ip": "192.0.2.10", "src_port": 40000}
{"bytes": 92400, "dst_ip": "198.51.100.20", "dst_port": 5001, "ifname": "eth0", "layer": "delivered", "packets": 77, "process_name": "ffmpeg", "src_ip": "192.0.2.11", "src_port": 40010}
```

Anonymized eBPF ingress sample captured on Linux:

```text
$ INTERFACE=eth0 harness/run.sh ebpf
ok: validated 1 rows from data/harness/udp_samples.ndjson
output: data/harness/udp_samples.ndjson
sqlite: data/harness/udp_samples.sqlite

{"bytes": 61, "dst_ip": "198.51.100.20", "dst_port": 58417, "ifname": "eth0", "layer": "ingress", "packets": 1, "src_ip": "203.0.113.53", "src_port": 53}
```

## Current Status

Implemented now:

- Python CLI skeleton
- deterministic `dry-run` collector
- generic UDP sample model and filters
- table and newline-delimited JSON output
- SQLite writer using WAL mode
- optional DuckDB writer
- optional Parquet writer through DuckDB
- ClickHouse HTTP JSONEachRow writer
- first eBPF C program for IPv4 UDP ingress counters at `tc` classifier attach
- eBPF collector that attaches with `tc`, drains counters with `bpftool`, and
  emits checkpoint deltas
- optional `/proc` socket/process enrichment for heuristic delivered-process
  rows
- basic Docker/ffmpeg harness files

Next implementation step:

- implement receive-side socket-cookie attribution with `fentry` preferred,
  `kprobe` fallback, and a delivered counter key of socket cookie plus UDP
  5-tuple

## Quick Start

Requires Python 3.9 or newer.

Run one dry-run checkpoint:

```sh
PYTHONPATH=src python3 -m udp_analyzer run
```

Run JSON output:

```sh
PYTHONPATH=src python3 -m udp_analyzer run --output json
```

Run for three seconds and save samples to SQLite:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --watch \
  --duration 3 \
  --output table \
  --storage sqlite \
  --db-path data/udp_analyzer.sqlite
```

Filter to delivered ffmpeg samples:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --output json \
  --process-name ffmpeg \
  --layer delivered
```

## Storage Targets

Primary local target:

- DuckDB/Parquet for local analytical captures

Implemented local fallback:

- SQLite WAL for small captures and harness runs

Primary networked target:

- ClickHouse for high-rate append-heavy history

See `storage.md` for the full storage decision.

Use SQLite:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --storage sqlite \
  --db-path data/udp_analyzer.sqlite
```

Use Parquet:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --storage parquet \
  --db-path data/udp_samples.parquet
```

## eBPF Build Sketch

The first eBPF program lives at `bpf/udp_ingress.bpf.c`.

On a Linux machine with clang and libbpf headers:

```sh
make -C bpf
```

Run the real eBPF collector on an interface:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --collector ebpf \
  --interface eth0 \
  --watch \
  --duration 10 \
  --output json
```

Add legacy heuristic process/socket enrichment from `/proc`:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --collector ebpf \
  --interface eth0 \
  --watch \
  --duration 10 \
  --output json \
  --enrich-processes
```

Filter legacy enriched rows to one process name:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --collector ebpf \
  --interface eth0 \
  --watch \
  --duration 10 \
  --output json \
  --enrich-processes \
  --process-name ffmpeg \
  --layer delivered
```

For CloudLinux/RHEL-like systems:

```sh
scripts/bootstrap-cloudlinux.sh
make -C bpf
```

For Ubuntu/Debian-like systems:

```sh
scripts/bootstrap-ubuntu.sh
make -C bpf
```

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run the dry-run harness:

```sh
DURATION=1 harness/run.sh dry-run
```

Run the eBPF harness on Linux:

```sh
INTERFACE=eth0 harness/run.sh ebpf
```

## Docs

- `PROJECT_GOAL.md`: product goal and first vertical
- `roadmap.md`: implementation phases
- `harness.md`: Dockerized ffmpeg validation target
- `storage.md`: local and networked storage design
