# Roadmap

This roadmap builds a universal eBPF UDP traffic analyzer first, then validates
it against the Dockerized `ffmpeg` vertical described in `harness.md`.

The project includes outbound TCP channel attribution (mainline) for a
deployment model where each systemd user unit owns exactly one configured URL.
The URL is configuration metadata, while eBPF measures the actual TCP socket
traffic.

## Current Implementation Status

Implemented:

- Python CLI, output modes, filters, and checkpoint loop
- dry-run collector for deterministic development
- eBPF IPv4 UDP ingress counter program for `tc` classifier attach
- Python eBPF collector using `tc` for attach and `bpftool` for map reads
- checkpoint deltas from absolute per-CPU BPF counters
- SQLite, DuckDB, Parquet, and ClickHouse writer interfaces
- process/socket enrichment from `/proc` by local UDP port and socket inode
  as a heuristic delivered layer
- dry-run and eBPF harness runners with JSON assertions
- CloudLinux/RHEL and Ubuntu/Debian bootstrap scripts
- TCP channel attribution scaffold for outbound systemd user-unit traffic:
  unit URL catalog, DNS resolution, `run-channels` CLI, TCP map parser, and
  fentry/fexit eBPF object/loader for socket byte counters

Still open:

- receive-side socket-cookie attribution with `fentry` preferred and `kprobe`
  fallback
- full Dockerized ffmpeg automated vertical with real containers
- robust same-port multi-process support such as `SO_REUSEPORT` or multicast
- production-grade retention/rollover for Parquet and remote databases
- Linux verifier validation for `bpf/tcp_channel.bpf.c` across the target kernel
  versions
- storage schema extension for channel fields if TCP channel history should be
  persisted alongside UDP rows

## Phase TCP-A: Configured HTTPS Channel Attribution

Goal: measure outbound HTTPS/TCP traffic per configured channel without parsing
or decrypting TLS.

Contract:

- one systemd user unit represents exactly one channel
- that unit exposes exactly one configured HTTP/HTTPS URL
- several units may point at the same `host:port`
- channel identity comes from the unit/cgroup, not from packet payload

Implemented baseline:

- read `.service` files from systemd user unit directories or explicit paths
- extract a single configured URL per unit and fail if a unit contains several
  URLs
- resolve configured hosts to A/AAAA addresses for endpoint validation
- add `run-channels` CLI with dry-run and eBPF collector modes
- add `ChannelTcpSample` rows with unit, channel, URL, host, socket cookie,
  cgroup ID, TCP byte counters, and `matched` / `unknown_unit` /
  `unexpected_flow` status
- add TCP eBPF hooks for `tcp_v4_connect`, `tcp_sendmsg`, `tcp_recvmsg`, and
  `tcp_set_state`
- add parser tests for the TCP channel BPF map layout

Still open:

- validate the TCP eBPF object with clang/libbpf/verifier on the target Linux
  kernels
- add IPv6 TCP key support in BPF and Python
- decide whether channel TCP rows need a separate storage table or a widened
  shared schema
- add an end-to-end Linux harness with throwaway systemd user units and a local
  HTTPS endpoint
- optionally accept application-level request events when a future unit needs
  more than one URL

## Phase 0: Project Skeleton

Goal: create a buildable minimal project shape for a reusable analyzer.

Deliverables:

- repository layout for eBPF code, Python user-space code, and harness files
- documented build prerequisites for Linux, clang/LLVM, libbpf, Docker, and
  ffmpeg
- a command that builds the eBPF object
- a command that runs a no-op Python analyzer and exits cleanly
- a stable CLI shape for output mode, bucket duration, and filters

Done when:

- a fresh Linux machine can build the empty analyzer
- required capabilities and privileges are documented
- the Python entry point can be run before eBPF details are added

## Phase 1: Packet-Level UDP Ingress Counters

Goal: count incoming UDP packets and bytes by generic packet fields.

Deliverables:

- eBPF program attached at an ingress-capable point
- extraction of source IP, destination IP, source port, destination port, and
  receiving interface
- BPF map keyed by packet-level UDP dimensions
- Python polling loop that emits time buckets
- JSON output mode for harness validation

Done when:

- generated UDP traffic appears in per-second buckets
- counts are separated by source IP
- counts are separated by destination IP
- counts are separated by source port
- counts are separated by destination port
- counts are separated by receiving interface

## Phase 2: Universal User-Space Reporting

Goal: make the analyzer useful without tying it to `ffmpeg`.

Deliverables:

- Python data model for time buckets and UDP dimensions
- newline-delimited JSON output for machines
- compact table output for humans
- filters for source IP, destination IP, source port, destination port, and
  interface
- documented byte accounting mode
- storage writer interface for checkpoint batches
- DuckDB/Parquet local storage target
- ClickHouse networked storage target

Done when:

- the same analyzer can inspect arbitrary UDP traffic
- output schema does not contain workload-specific fields unless enrichment is
  enabled
- filters work before Docker or process attribution exists
- checkpoint rows can be persisted locally and to a networked database

## Phase 3: Socket, Process, and Namespace Attribution

Goal: add optional delivery-side attribution for sockets, processes, and
containers.

Deliverables:

- selected attach point for receive-side process or socket attribution
- stable socket identifier, preferably socket cookie when available
- mapping from socket identifier to process identity
- mapping from host PID to container PID, container ID, and network namespace
- optional output fields for socket ID, process name, host PID, container PID,
  container ID, and namespace ID

Done when:

- traffic delivered to different UDP sockets can be separated
- traffic delivered to different processes can be separated
- process identity remains understandable after namespace translation
- traffic to unopened UDP ports is not falsely attributed to a process

Current status: the implemented `/proc` enrichment is a port-based heuristic. It
can label simple delivered rows, but it is not exact receive-side attribution.

## Phase 3A: Receive-Side Socket Cookies

Goal: replace heuristic delivered attribution with kernel receive-side
attribution keyed by the socket selected by UDP demultiplexing.

Implementation direction:

- prefer `fentry` on a UDP receive-path function that exposes the selected
  `struct sock *` and packet context
- fall back to `kprobe` when `fentry` or BTF is unavailable but a usable kernel
  symbol exists
- use socket cookie as the stable socket identifier
- key the delivered map by socket cookie plus UDP 5-tuple
- keep current `/proc` local-port enrichment as a legacy/fallback mode
- map socket cookie to process, host PID, container PID, container ID, and
  network namespace from user space

Done when:

- delivered rows are emitted from receive-side counters rather than local-port
  correlation
- two sockets sharing one UDP port can be counted separately
- unopened-port traffic remains ingress-only and is not labeled delivered
- unsupported kernels fail with actionable messages and can fall back to legacy
  enrichment when requested

## Phase 4: Dockerized ffmpeg Vertical

Goal: use the universal analyzer for the defined ffmpeg-in-Docker workload.

Deliverables:

- `harness/compose.yaml`
- `harness/start_ffmpeg.sh`
- `harness/send_udp.py`
- `harness/run.sh`
- deterministic streams for at least three UDP destination ports
- enrichment or filters that isolate Dockerized `ffmpeg` processes

Done when:

- one Docker container runs at least three `ffmpeg` receiver processes
- multiple `ffmpeg` processes in one Docker instance produce separate buckets
- source IP, destination port, and interface remain visible for delivered traffic
- traffic to unopened UDP ports appears as ingress traffic but not as
  delivered-to-ffmpeg traffic

## Phase 5: Assertions and Regression Tests

Goal: make the harness automatically decide pass or fail.

Deliverables:

- `harness/assert_output.py`
- expected traffic manifest generated by `harness/run.sh`
- count tolerance rules for packets, bytes, and bucket boundaries
- CI-friendly smoke mode with short runtime

Done when:

- packet counts are exact in controlled local tests
- byte counts are exact for the documented byte accounting mode
- time-bucket drift is tolerated only at stream boundaries
- regressions in source, port, interface, or process attribution fail the harness

## Phase 6: Correlated Ingress and Delivery View

Goal: show both what arrived at the host and what reached each process.

Deliverables:

- clear distinction between ingress counters and delivered counters
- correlation strategy between packet-level keys and socket/process-level keys
- output schema that can represent both layers
- summary totals that compare ingress and delivery

Done when:

- dropped or unopened-port traffic can be identified
- totals can be compared between ingress and delivered layers
- the same correlation model works for ffmpeg and non-ffmpeg UDP workloads

## Phase 7: Operational Polish

Goal: make the tool useful during real debugging.

Deliverables:

- readable live table output
- filters for source IP, destination IP, ports, interface, namespace, container,
  and process
- configurable bucket duration
- graceful shutdown with final counter flush
- clear error messages for missing privileges, missing BTF, or unsupported kernel
  features

Done when:

- an operator can run the analyzer during a live UDP workload
- output can be filtered down to one problematic stream or process
- unsupported environments fail with actionable messages

## Open Technical Questions

- Which attach point gives the best balance of packet fields, socket identity,
  and process context?
- Should byte counts mean UDP payload bytes, IP packet bytes, or link-layer
  bytes?
- How much correlation should happen in eBPF maps versus user space?
- Which parts of loading and enrichment should stay in Python, and which require
  a small native helper?
- Should short-lived `ffmpeg` process metadata be cached after process exit?
- Should same-port multi-process workloads be supported with `SO_REUSEPORT` or
  multicast in the first production version?
