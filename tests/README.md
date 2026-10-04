# Tests

Interop and attack harnesses for the from-scratch HTTP/3 stack. Every harness drives the demo host
(`samples/H3Server`) as a **separate process over real UDP**, and the two gated ones do it with a
client nobody here wrote.

## Running everything

```bash
tests/run-tests.sh
```

One runner, in bash, on every platform — including Windows, under the Git Bash
that ships with Git for Windows. The PowerShell twin was removed on 2026-09-23;
the header of that script says why.

The runner builds the demo host and the harnesses, starts the host on `:4433`, drives one process
per harness and prints a pass/fail summary. Flags: `-NoBuild`/`--no-build` (assume a current Release
build), `-Filter`/`--filter <substr>`, `-Port`/`--port <n>`.

Two scripts, one job — the same arrangement the HTTP/2 repository uses for `autobahn` and `h2spec`.
The development machine is Windows; the Debian container CI's second leg runs in has no `pwsh`. Each
is exercised by the leg it belongs to, so neither can rot unnoticed, but they *are* two
implementations of one thing: a change to either belongs in both.

On Debian, `h3semantics` reports **SKIP** — `System.Net.Quic` finds no libmsquic in the bare
container. `h3attack` needs no QUIC client at all and runs in full there: 13/13, including version
negotiation, the amplification limit and stateless-reset sizing, on the platform this runs on in
production.

Current status: **38/38 checks pass**, and `ci.yml` runs this on every push. It started at 37/38:
see [What this found](#what-this-found).

The in-process unit and integration tests — RFC 9000/9001/9002/9114/9204 vectors, the TLS 1.3 key
schedule, QPACK, the frame state machine, "evil" raw-QUIC peers, a seeded lossy link — live with the
stack in Hermod (`HermodTests/HTTP3/`, 249 tests) and are what `ci.yml` gates on. They are far more
thorough than anything here. What they cannot be is *independent*: both ends of every one of them
is our own code, sharing one reading of the RFCs and one set of bugs.

That is the gap this directory fills, and why the findings below came from it rather than from the
249.

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

## What this found

**`h3semantics`: a connection stalled after exactly 100 requests.** ✅ Fixed.

Each HTTP/3 request takes a fresh bidirectional QUIC stream, and stream IDs are never reused. The
transport parameter `initial_max_streams_bidi` grants the first 100; after that the peer needs more
credit via `MAX_STREAMS` as earlier streams complete (RFC 9000 §4.6, §19.11). Hermod *parsed*
`MAX_STREAMS` and logged it to qlog, but `new MaxStreamsFrame(...)` appeared nowhere outside the
parser — it was never sent. So request 101 on any connection waited for credit that never arrived
and died at the idle timeout: the transport parameter was not an opening grant but the lifetime
budget of the connection. A browser tab reaches that on one page.

It went unnoticed because nothing had ever run 100 requests over a single HTTP/3 connection — the
in-process suite works in tens, and `curl`, Chrome and Edge each open a connection per run. Fixed in
[Hermod#20](https://github.com/Vanaheimr/Hermod/pull/20) with six tests of its own; the check here
stays as the regression guard, because it is the one that noticed.

**`h3bench` (not gated): large uploads were slow and eventually fatal.** ✅ Fixed.

300 000 bytes down took ~11 ms; the same 300 000 bytes up took ~130 ms on a good run and ~830 ms
on a bad one, after which the connection was lost to the idle timeout mid-upload — one measured run
died at 40 of 50. Receiving large request bodies stalled somewhere that sending them did not.

The somewhere was the acknowledgment cadence. `DelayedAcknowledgments` defaulted to true, so the
server held acknowledgments back per RFC 9000 §13.2.2 whether or not the peer had ever asked for
that — and a slow-start sender lives from the acknowledgment of every small flight, so any flight
whose tail sat out `max_ack_delay` stalled its congestion window. The held acks also fed the
uploader's RTT estimator samples of 10–30 ms on a 0.5 ms path, from which msquic sized its
flow-control grants: 6 KB slices every 2.3 ms. A second bug surfaced while measuring the first:
the §13.2.1 out-of-order check compared arrivals against the largest ack-*eliciting* packet rather
than the largest *received* one, so the ack-only tail of every request/response turn manufactured
a phantom hole that forced an immediate ACK — quietly defeating both delayed acknowledgments and
any cadence a peer requested.

Fixed in Hermod 87a561d5, *"Acknowledge promptly by default, and delay only when the peer asks"*:
the data sender is the one that knows what cadence its loss recovery can afford, which is the
ack-frequency draft's control model, so a receiver only delays when ACK_FREQUENCY tells it to.
Measured at the current pin: 47–66 ms per 300 000-byte round trip across three fresh runs,
150/150 uploads, no degradation, no deaths. The two findings above went through two weeks of
in-process tests without a ripple — both ends were ours, on moving fake clocks. The first foreign
stack to drive this server put a number on each of them within an afternoon.

**`h3bench` (not gated): throughput falls as concurrency rises.** ⬜ Open.

~35 MiB/s with one `GET /big` in flight, ~10 MiB/s with 32 — on loopback, where more streams have
no propagation delay or loss to hide behind. The acknowledgment fix did not change this in kind,
so it stops being a footnote to the upload finding and becomes its own.

## Benchmarks (h3bench)

```bash
dotnet run --project samples/H3Server -- 4433
```
```bash
dotnet run --project tests/h3bench --configuration Release
```

Everything else in this repository has a number behind it — 247 unit tests, 38/38 harness checks,
8 foreign stacks, Chrome and Edge 8/8. Performance had none, which made "readable rather than fast"
an assumption rather than a finding. Loopback measures our packet handling, framing and crypto, not
a network, and the msquic client's cost sits inside every figure: comparing two runs of this file is
meaningful, comparing it to a datacentre benchmark is not.

Baseline on a 16-core Windows 11 machine, .NET 10.0.401, measured 2026-10-04 at Hermod pin
22768a4a — after the acknowledgment-cadence fix; the pre-fix numbers live in the finding above.
Median of three runs:

| Measurement | Result |
|---|---|
| `GET /big` (300 000 B), sequential | ~30 MiB/s, ~9.5 ms/request |
| `POST /echo` (300 000 B, echoed) | ~9 MiB/s, 47–66 ms/round trip |
| `GET /` latency, 90 requests | p50 0.35 ms · p90 0.43 ms · p99 7.7 ms |
| `GET /` sustained | ~2 250 requests/s |
| `GET /big`, 1 → 32 in flight | ~35 → ~10 MiB/s |

That last row is the open finding above: throughput should not fall by ~70 % as concurrency rises
on loopback. The rest of the table moved the way the fix predicts — the round trip that was ~130 ms
and sometimes ~830 ms now sits under 70 ms every time — while latency and sustained request rate
stayed where they were, which is what you want from a change that only touches when acks go out.
