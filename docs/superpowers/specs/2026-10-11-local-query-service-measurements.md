# JAM-255 benchmark findings

Three finite deterministic synthetic scale proxies were run sequentially in independent Python processes. Counts, query results, and SQLite integrity checks passed at all scales. Artifacts are throwaway, with no production edits or dependency installations. The results below were retained from the earlier spike run; they were not rerun on 2026-10-13. Hardware: Apple M3 / 8 logical CPUs / 16 GiB RAM, macOS 26.6.2 ARM64; Python 3.9.6 / SQLite 3.51.0 (measurement-only runtime). Methodology is recorded [below](#methodology-and-local-rerun-commands); complete schema, plans, raw timings, correctness assertions and resource observations are in the three [retained JSON files](#retained-raw-evidence).

Harness SHA-256: `535e4339f6a12ff1d1566f500dc8bb4174f32e295195f8582f72c06227106ce2`.

| Synthetic packets / 60-second pps proxy | 60,000 / 1,000 | 600,000 / 10,000 | 6,000,000 / 100,000 |
|---|---:|---:|---:|
| Source generation, seconds | 0.02454 | 0.22870 | 2.64187 |
| Source scan + header decode, seconds | 0.06709 | 0.71413 | 7.23627 |
| Source scan + header decode, us/packet | 1.118 | 1.190 | 1.206 |
| Import + four maintained indexes, seconds | 0.22103 | 5.46289 | 185.14398 |
| Import, us/packet | 3.684 | 9.105 | 30.857 |
| Import, achieved packets/second | 271,458 | 109,832 | 32,407 |
| Explicit final checkpoint, ms | 0.212 | 0.792 | 5.709 |
| Subsequent ANALYZE, ms | 11.793 | 127.452 | 17,052.965 |
| Source bytes | 5,760,048 | 57,600,048 | 576,000,048 |
| Database bytes | 9,498,624 | 98,840,576 | 1,004,785,664 |
| Database bytes/packet | 158.310 | 164.734 | 167.464 |
| Source + database bytes/packet | 254.311 | 260.734 | 263.464 |
| Observed WAL bytes before final checkpoint | 4,556,752 | 16,681,912 | 21,110,912 |
| Peak process RSS, bytes | 33,931,264 | 66,486,272 | 56,623,104 |

Warm query timing is 20 measured repeats after a separately recorded first query; nearest-rank quantiles. Source generation/import/verification prewarm files. OS cache was not dropped, so neither first queries nor these results describe cold-cache latency. Request bodies, JSON/IPC, browser rendering and full packet detail decoding are excluded.

| Warm query p50 / p95 / max, ms | 60k | 600k | 6m |
|---|---:|---:|---:|
| Time-first page (200 rows) | .080 / .084 / .084 | .074 / .076 / .078 | .081 / .084 / .085 |
| Midpoint keyset page (200 rows) | .082 / .086 / .087 | .078 / .095 / .135 | .083 / .086 / .089 |
| Flow-first page (15 / 147 / 200 rows) | .018 / .020 / .021 | .114 / .116 / .121 | .135 / .144 / .162 |
| Protocol + port, newest-first (200 rows) | .110 / .120 / .131 | .110 / .112 / .112 | .113 / .118 / .120 |
| Whole-capture aggregate/top10 | 12.160 / 12.284 / 12.343 | 162.071 / 180.660 / 191.185 | 2241.141 / 2396.843 / 2453.847 |

| First query, uncontrolled cache, ms | 60k | 600k | 6m |
|---|---:|---:|---:|
| Time-first page | .101 | .100 | .121 |
| Midpoint keyset | .098 | .097 | .121 |
| Flow-first page | .036 | .288 | .421 |
| Protocol + port, newest-first | .131 | .124 | .127 |
| Whole-capture aggregate/top10 | 12.092 | 164.013 | 2284.552 |

First committed 5000-row page was observed 13.703 / 13.653 / 14.230 ms after *import began*, excluding prior source generation/scan. Between-commit page observations at 3m and 6m rows in the largest run took 4.892 and .655 ms; these are stronger evidence than final warm pages for partial-import responsiveness, but readers were not running concurrently with the writer. The indexed midpoint 200-packet source seek/read p95 was .157 / .158 / .196 ms; offsets are nearby contiguous packets, not random distributed blocks.

All page queries use an explicit time, flow, or protocol+port index. The aggregate scans the flow index and uses a temporary B-tree for ORDER BY. The 50 ms cooperative interrupt probe stopped at 50.027 / 50.124 / 50.177 ms and the connection remained reusable. It is a bounded SQLite VM demonstration, not a wall-clock guarantee for blocking I/O or a tested application cancellation path.

These measurements support a provisional SQLite metadata-index prototype for paginated reads. They do not establish production capture capacity. At 6m, import alone took 185 s for the nominal 60 s / 100kpps source and ANALYZE took another 17 s; no sustained live claim is justified. Whole-capture aggregates exceed a 250 ms interactive budget at 6m and should use bounded/precomputed summaries or an asynchronous job. No DuckDB runtime was installed, so no empirical cross-engine performance comparison is available.


## Retained raw evidence

- [60,000 packets](2026-10-11-local-query-service-measurement-60000.json); SHA-256 `cc5a2ca0dd8bf776c456a2bb57d3b6baf1812ebc7defc9fe9e8167453413fa21`.
- [600,000 packets](2026-10-11-local-query-service-measurement-600000.json); SHA-256 `38032f36850c725ea2c239eebf6b886efb5d1f699cf5e9562c7ed6a9040029e8`.
- [6,000,000 packets](2026-10-11-local-query-service-measurement-6000000.json); SHA-256 `7694cc5c17cbeba8bc7d31cfec8e926964ec79392f83098e4bec0f08c572ea53`.

## Methodology and local rerun commands

The harness and generated packet/database artifacts remain outside the repository. Raw measurement JSON is retained here as evidence; it is not production code.

**Reproducibility limitation:** the exact harness source is retained only at `/private/tmp/jam255-bench/bench.py` on this machine, outside the repository per the task contract. It may be removed by temporary-directory cleanup or reboot. A clean clone cannot reproduce these numbers from the retained documents/JSON alone; the harness SHA-256 anchors the original source but cannot recover it. The commands below work only while that local file exists. Merging benchmark source would require James to change the contract; no such permission is assumed. A follow-up benchmark must retain a reviewed reproducible harness under its own approved scope.

The original local commands ran three sequential, independent processes (fresh output directory or unused packet counts required; existing databases intentionally cause an error):

```sh
mkdir -p /private/tmp/jam255-bench-repeat
python3 /private/tmp/jam255-bench/bench.py --n 60000 --reps 20 --dir /private/tmp/jam255-bench-repeat
python3 /private/tmp/jam255-bench/bench.py --n 600000 --reps 20 --dir /private/tmp/jam255-bench-repeat
python3 /private/tmp/jam255-bench/bench.py --n 6000000 --reps 20 --dir /private/tmp/jam255-bench-repeat
```

Original invocation used the default `/private/tmp/jam255-bench` output directory. No dependencies were installed. No repository tests ran concurrently. The only simultaneous observations were lightweight filesystem inspection and report writing. Hardware: Apple M3, 8 logical CPUs, 16 GiB RAM; macOS 26.6.2 ARM64; Python 3.9.6, stdlib SQLite 3.51.0. Exact interpreter/platform and harness SHA-256 are in each `result-<n>.json`. System specification command was `sysctl -n hw.memsize hw.ncpu machdep.cpu.brand_string`; no hostname was collected.

The native-shaped pcapng source contains one 28-byte section header, one 20-byte Ethernet interface block (default microsecond timestamps), then 96-byte enhanced packet blocks holding 64-byte captured/original frames. Every frame is deterministic Ethernet/IPv4 with TCP (10-byte payload) or UDP (22-byte payload); source and transport checksums are populated. The source uses 4096 repeated unidirectional tuples and documentation/synthetic addresses, alternating TCP/UDP; TCP destinations alternate 443/80, UDP 53/123. Templates repeat packet sequence numbers and are valid standalone frames, not valid replay sessions. Timestamps span just under 60 seconds. Counts 60k,600k,6m therefore label 1k/10k/100k pps *synthetic scale proxies*, not representative home/office/datacenter captures or production capacity claims.

The fixture is valid minimal pcapng rather than an exact repository writer output: it omits the writer's 8-byte EPB direction option and 4-byte options terminator (12 bytes/packet), interface-name/timestamp-resolution options, application metadata, and interface statistics. The repository writer uses nanoseconds, whereas this minimal IDB relies on pcapng's default microseconds. Actual writer output for the same 64-byte frames would therefore start at 108 rather than 96 bytes/packet before section/interface/statistics overhead. Storage budgets must include actual source bytes, rather than treating the measured combined bytes/packet as universal.

The reader deliberately recognizes only this fixed source shape. It checks block framing and Ethernet/IPv4 shape, reads transport ports, and emits metadata rows. It does not implement the repository Rust parser, general pcapng import, malformed file handling, IPv6, other linktypes, field registry/summary formatting, enrichment, flow lifecycle/reassembly, TLS, or application decoding. Classic PCAP is not measured. No payload is stored in SQLite; exact source offsets allow bounded source-byte lookup.

Each database has 15 scalar columns (`id`, timestamp, interface, block/data offsets, captured/original lengths, EtherType, IP version/protocol, integer IPv4 addresses, ports, synthetic flow id) and four maintained indexes: time+id, flow+time+id, protocol+destination-port+time+id, wire-length-descending+time+id. Schema and actual plans are in every raw JSON. IPv4 address integers and one interface understate richer production schemas. The length index is maintained for ingest/storage cost but not exercised by the current query set because all frames are fixed-size. The main filter query uses protocol+port and descending time. The 4096 fixed flow IDs make aggregate/index behavior less adversarial than a scan or spoofed-source workload with very high flow cardinality: that attacker can increase grouping state, flow-index churn and temporary sorting pressure. The 2.2-second aggregate result therefore is not a worst-case bound.

Import uses 5000-row batches, one writer/checkpointer, WAL, NORMAL synchronous mode, 32 MiB SQLite page-cache target, mmap disabled, file temporary storage, and 1000-page automatic checkpoint target. Batches are decoded from buffered source reads without retaining the whole capture. Generation includes a final source `fsync` and is reported separately. Timed scan/decode is an independent full source pass. Timed import includes a second header scan/decode, insertion, four index updates, transaction commits, automatic checkpoints, and three small progress observations (at 5000,half,total rows). Final explicit checkpoint and `ANALYZE` durations are reported separately. Thus import pps is neither steady-state capture capacity nor durable-production write throughput; synchronous FULL and mixed concurrent workloads remain unmeasured.

The read-only between-batch connections demonstrate visibility of committed first pages, with count assertions; they do not demonstrate readers running concurrently during writes. Record their wall time as first-page *observations*, including file-generation and independent source-scan costs separately rather than claiming immediate first page from process start.

Queries fetch up to 200 metadata rows for first time page, midpoint keyset page, one flow, and protocol+port filter ordered newest-first. The full aggregate/top-ten sums original bytes grouped by all 4096 flow IDs. Each records its first invocation plus 20 repeated warm wall-clock timings, nearest-rank p50/p95/max and raw samples. Rows are fetched into memory and verified against deterministic expectations; SQLite integrity check, total count, sum(id), and protocol+port count must match. Integrity checking and ANALYZE occur before query measurement. Source generation, source scan, import, and correctness checks prewarm files, and OS caches are not dropped. The first-query observation is emphatically not a cold-cache result. SQLite connection/page cache is reused for repeats; no JSON/IPC/browser rendering is included. Separately, 200 source seeks/64-byte reads use indexed midpoint offsets; this avoids the full raw-file scan but these source offsets are contiguous packets in the midpoint page, not randomly distributed source blocks. It does not measure scattered per-flow source reads or full packet detail rendering.

Cancellation sets a monotonic 50 ms deadline with SQLite's progress handler every 1000 VM instructions, then executes an intentionally huge cross join. The harness requires the `interrupted` error and verifies subsequent connection reuse. It demonstrates cooperative VM interruption; blocking filesystem calls, HTTP disconnect plumbing, concurrent cancellation, and production driver behavior are not covered.

SQLite 3.51.0 is a measurement runtime only. The parent records the official WAL-reset corruption fix and requires a patched pinned version plus repeat benchmarks for any production selection. The measured setup uses a single writer/checkpointer and does not exercise competing checkpoint/writer connections.

Peak RSS is process lifetime `resource.getrusage(RUSAGE_SELF).ru_maxrss` in bytes on macOS, including generation, import, query verification, and aggregate. SQLite cache target is not a hard process-memory cap. File sizes include source and final checkpointed database, with WAL bytes immediately before the final checkpoint separately. That WAL field is an observation, not the high-water mark. Scratch totals and raw samples live in JSON; aggregate temp files are transient and not high-water instrumented. Filesystem cache and unrelated host processes are excluded from process RSS. Retain these caveats when deriving provisional packet/byte/memory/query budgets.

## How the measurements inform proposed limits

The decision record proposes a 200-row default page, a 1000-row hard maximum, a 1-second interactive deadline, a 256 MiB worker ceiling, a 32 MiB SQLite cache target and a 2 GiB derived-artifact quota. Only 200-row pages, a 32 MiB cache target and cooperative interruption were measured. The larger page ceiling, worker ceiling and artifact quota are conservative design candidates requiring explicit enforcement tests; they are not measured safe limits. The earlier harness report suggested a smaller 600,000-packet/128 MiB prototype job, 128 MiB memory target and 250 ms deadline. Those are useful initial validation points, not adopted retention defaults. The decision uses resource budgets rather than declaring six million packets supported: import may pause at a committed boundary, and queries that cannot complete within budget must fail or use a separately approved bounded job.

Neither policy establishes sustained packet ingest at the three nominal rates. The 6m run falls behind its 60-second source window before accounting for production decoding, concurrent capture or FULL durability.

## Validation refresh (2026-10-13)

Executed in the JAM-255 worktree at `fce195e0d87dac6fb3d14cec5b459ab3b7efc141`. The 2026-10-11 performance runs were not rerun; their original JSON was retained byte-for-byte. This refresh verifies evidence, source boundaries and existing behavior, not a query-service implementation.

| Command / check | Actual result |
| --- | --- |
| Python stdlib evidence validation against original `/private/tmp/jam255-bench/result-{n}.json` and `bench.py` | All three JSON copies identical; harness hash matches; row count, sum(id), filter count, reported integrity result, source-size formula, import cost math, 20-sample quantiles and cancellation assertions checked. This checks recorded results, not a fresh database integrity run. |
| Regenerate 4096 frame templates in memory and check IPv4 + TCP/UDP pseudoheader checksums | All checks pass; no new capture/database generated. |
| Local Markdown link existence checks | All new local links resolve. |
| `npx vitest run lib/__tests__/display-filter.test.ts lib/__tests__/agent-auth.test.ts lib/__tests__/agent-client-auth.test.ts lib/__tests__/same-origin.test.ts lib/__tests__/host-allowlist.test.ts lib/__tests__/stream-decrypted-gating.test.ts lib/__tests__/decrypted-export-exclusion.test.ts --maxWorkers=1` | PASS: 7 files / 88 tests. |
| `cargo test --locked --test no_disk_write_invariant --test pcapng_roundtrip` | PASS: 6 tests. |
| `cargo test --locked -- --test-threads=1` | PASS: 487 tests, 10 ignored across unit/integration suites; ignored tests need live privileges or exclusive port 9990 and were not run. |
| `npx vitest run --maxWorkers=1` | Exit 1: all 82 files / 602 assertions passed, but runner reports unhandled `read ECONNRESET` in `enrichment-whois-client.test.ts`. |
| `npx vitest run lib/__tests__/enrichment-whois-client.test.ts --maxWorkers=1` | Exit 1: 6 assertions passed; same unhandled error reproduced. |
| `npx vitest run` | Exit 1: all 82 files / 602 assertions passed; same unhandled error. Full TypeScript suite is **not green**. |
| Loopback-only Node timeout diagnostic with accepted/client socket error observers | Sandbox listener initially rejected with EPERM; rerun after tool approval exited 0 and did not reproduce ECONNRESET. No definite socket provenance established. |
| `git diff --check` | PASS; repeated after final documentation edits. |
| Independent security/source/evidence review | At-rest disclosure gap fixed and re-reviewed; no remaining findings. Reviewer did not run suites or benchmarks. Claude cross-review approved the corrected record on 2026-10-13 at 11:50 EDT; no remaining required changes. Optional harness attachment is not authorized or completed. |

The WHOIS test fixture accepts sockets without an error listener, whereas the production WHOIS client installs one. This is a plausible fixture-error source, not a proven root cause from the runner stack. The same error is recorded in historical TEST_STATUS. No unrelated fixture or production file was changed; a separate scoped test fix is needed before claiming clean broader validation. Tests were not ignored or suppressed to obtain a green result.

Official SQLite WAL/appropriate-use and DuckDB concurrency/limits documentation was rechecked on 2026-10-13. The recommendation requires a pinned patched SQLite runtime; the measured runtime is not approved for production.


## Consequence for high-rate deployments

The 6m run measured 167.464 bytes per packet of derived database and approximately 32,407 packets/s of import. Dividing the proposed 2 GiB quota by that database cost yields an **optimistic arithmetic ceiling** of about 12.82 million indexed packets; it excludes WAL/temp/rebuild reservations and assumes the same small schema/traffic distribution. The quota actually covers those artifacts, so usable capacity is lower. At 100,000 packets/s that ceiling is about 128 seconds of traffic, while this import cannot keep pace even before production decoding. These are extrapolations from a measured finite dataset, not measurements at those link rates.

For illustrative 10 Gbit/s serialization scenarios, assume 8-byte preamble/SFD and 12-byte inter-frame gap: `10^10 / (8 * (64 + 8 + 12))` gives about 14.88 million minimum-size frames/s and `10^10 / (8 * (1518 + 8 + 12))` gives about 0.813 million frames/s for a 1500-byte payload Ethernet frame. Under the same optimistic row-cost assumption, the index quota covers about 0.86 seconds or 15.8 seconds respectively. No 10GbE workload was measured, and jumbo frames, encapsulation and richer indexes change these figures. Raw-source bytes consume separate storage and can be much larger.

Consequently, this prototype does **not** justify whole-capture per-packet indexing as the default on sustained high-rate WAN/datacenter links. An explicitly selected small finalized capture remains useful for incident analysis; unrestricted indexing creates unacceptable backlog/quota pressure. A follow-up must measure bounded time-window/flow-subset imports and flow/metric-rollup indexing, expose selection/coverage, and choose a high-rate default with James. Reducing stored rows also does not remove source preflight/scan cost without a trusted source/segment index; measure that cost separately. None of these strategies silently enable always-on recording or change capture BPF.

**Open optimization:** the harness maintains four indexes during insertion. For finalized-file imports, bulk-load then build indexes is a plausible alternative, but it was not measured. A follow-up must compare import time, first-query availability, peak temp/disk/memory, cancellation and crash recovery before adopting it. The 4096-flow distribution also needs a high-cardinality comparison before selecting aggregate or ingest budgets.
