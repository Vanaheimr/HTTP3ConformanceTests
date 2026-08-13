# Tests

Interop and attack harnesses for the from-scratch HTTP/3 stack. Every harness drives the demo host
(`samples/H3Server`) as a **separate process over real UDP**, and the two gated ones do it with a
client nobody here wrote.

## Running everything

```bash
pwsh tests/run-tests.ps1
```

The runner builds the demo host and the harnesses, starts the host on `:4433`, drives one process
per harness and prints a pass/fail summary. Flags:

- `-NoBuild` — skip the build step (assumes a current Release build).
- `-Filter <substr>` — only run harnesses whose name matches.
- `-Port <n>` — use a different UDP port.

Current status: **37/38 checks pass**. The one failure is real and is described under
[Known failures](#known-failures) — it is a gap in the stack, not a flaky harness.

The in-process unit and integration tests — RFC 9000/9001/9002/9114/9204 vectors, the TLS 1.3 key
schedule, QPACK, the frame state machine, "evil" raw-QUIC peers, a seeded lossy link — live with the
stack in Hermod (`HermodTests/HTTP3/`, 247 tests) and are what `ci.yml` gates on. They are far more
thorough than anything here. What they cannot be is *independent*: both ends of every one of them
is our own code, sharing one reading of the RFCs and one set of bugs.

That is the gap this directory fills, and why both findings below came from it rather than from the
247.

## The harnesses

| Harness | Kind | Client side | Covers |
|---|---|---|---|
| `h3semantics` | demo-driven, gated | .NET `HttpClient` over **msquic** | RFC 9114 semantics: status/headers/trailers, 300 KB download byte-exact, request bodies from 16 B to 300 KB, `MAX_FIELD_SECTION_SIZE`, connection reuse, 16 concurrent streams, long-lived connections (25 checks) |
| `h3attack` | demo-driven, gated | hand-built UDP datagrams | noise, undersized Initials (§14.1), version negotiation + GREASE (§6.1/§6.3), stateless reset sizing (§10.3.3), the 3× amplification limit (§8.1), a 128-source flood, a cancellation storm (13 checks) |
| `h3bench` | benchmark, not gated | .NET `HttpClient` over **msquic** | throughput up and down, latency percentiles, concurrency scaling — no verdict, just numbers |
| `h3interop` | live network, not gated | our own client, outbound | the client interop matrix against 8 public HTTP/3 servers — see [INTEROP.md](../INTEROP.md) |

**Why msquic.** `h3semantics` deliberately has no `ProjectReference` to Hermod. Its client is
Microsoft's QUIC stack, reached through .NET's own `HttpClient`, so every check it passes is two
independent implementations agreeing on RFC 9114 — and it puts a fourth foreign client on our
server, next to the two `curl` builds and Chromium. On a machine without QUIC support it reports
SKIP (exit code 2) rather than a green 0/0.

**Why raw UDP.** `h3attack` has no `ProjectReference` either, though its HTTP/2 counterpart does.
Borrowing our own packet builders to attack our own server would test the server against the code
that produced its input. Everything it sends is hand-built bytes.

Both gated harnesses end every scenario by checking that the server *still serves a normal request*.
A hardening check that only proves "no reply came back" would pass just as happily against a server
that had crashed.

## Known failures

**`h3semantics`: 120 requests on one connection — stalls after exactly 100.**

Each HTTP/3 request takes a fresh bidirectional QUIC stream, and stream IDs are never reused. The
transport parameter `initial_max_streams_bidi` grants the first 100; after that the peer needs more
credit via `MAX_STREAMS` as earlier streams complete (RFC 9000 §4.6, §19.11). Hermod *parses*
`MAX_STREAMS` and logs it to qlog, but `new MaxStreamsFrame(...)` appears nowhere outside the
parser — it is never sent. So request 101 on any connection waits for credit that never arrives and
dies at the idle timeout, and the connection is capped at 100 requests for its whole life. A browser
tab reaches that on one page.

It went unnoticed because nothing had ever run 100 requests over a single HTTP/3 connection: the
in-process suite works in tens, and `curl`, Chrome and Edge each open a connection per run.

**`h3bench` (not gated): large uploads are slow and eventually fatal.**

300 000 bytes down takes ~11 ms; the same 300 000 bytes up takes ~130 ms on a good run and ~830 ms
on a bad one, after which the connection is lost to the idle timeout mid-upload. Receiving large
request bodies stalls somewhere that sending them does not. Not a pass/fail item, which is precisely
why nothing had caught it.

## Benchmarks (h3bench)

```bash
dotnet run --project samples/H3Server -- 4433
```
```bash
dotnet run --project tests/h3bench --configuration Release
```

Everything else in this repository has a number behind it — 247 unit tests, 37/38 harness checks,
8 foreign stacks, Chrome and Edge 8/8. Performance had none, which made "readable rather than fast"
an assumption rather than a finding. Loopback measures our packet handling, framing and crypto, not
a network, and the msquic client's cost sits inside every figure: comparing two runs of this file is
meaningful, comparing it to a datacentre benchmark is not.

Baseline on a 16-core Windows 11 machine, .NET 10.0.400:

| Measurement | Result |
|---|---|
| `GET /big` (300 000 B), sequential | ~25 MiB/s, ~11 ms/request |
| `POST /echo` (300 000 B, echoed) | ~4 MiB/s, ~130 ms/round trip |
| `GET /` latency, 90 requests | p50 0.35 ms · p90 0.46 ms · p99 6.97 ms |
| `GET /` sustained | ~2 200 requests/s |
| `GET /big`, 1 → 32 in flight | 62 → 22 MiB/s |

That last row is its own finding: throughput should not fall by two thirds as concurrency rises on
loopback.
