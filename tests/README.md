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
per harness and prints a pass/fail summary. Flags: `-n`/`--no-build` (assume a current Release
build), `--filter <substr>`, `--port <n>`, and `--require-all`, which counts a SKIP as a failure.

Both harnesses run on both CI legs. On Linux `h3semantics` needs libmsquic, which Debian does not
ship; the Debian 13 container installs it from packages.microsoft.com. Until 2026-10-29 it did
not, so `h3semantics` reported SKIP there, and every msquic check, the upload guard for Hermod#129
included, ran on Windows alone. A SKIP counts as a pass, so that leg stayed green the whole time.
CI therefore runs with `--require-all`: a container in which libmsquic stops loading now fails.

Current status: **42/42 checks pass**, and `ci.yml` runs this on every push. It started at 37/38:
see [What this found](#what-this-found).

The in-process unit and integration tests — RFC 9000/9001/9002/9114/9204 vectors, the TLS 1.3 key
schedule, QPACK, the frame state machine, "evil" raw-QUIC peers, a seeded lossy link — live with the
stack in Hermod (`HermodTests/HTTP3/`, 337 tests) and are what `ci.yml` gates on. They are far more
thorough than anything here. What they cannot be is *independent*: both ends of every one of them
is our own code, sharing one reading of the RFCs and one set of bugs.

That is the gap this directory fills, and why the findings below came from it rather than from the
337.

## The harnesses

| Harness | Kind | Client side | Covers |
|---|---|---|---|
| `h3semantics` | demo-driven, gated | .NET `HttpClient` over **msquic** | RFC 9114 semantics: status/headers/trailers, 300 KB download byte-exact, request bodies from 16 B to 300 KB, `MAX_FIELD_SECTION_SIZE`, connection reuse, 16 concurrent streams, long-lived connections, large uploads on fresh connections, a path cut mid-response so that only the server's own timers can act (29 checks) |
| `h3attack` | demo-driven, gated | hand-built UDP datagrams | noise, undersized Initials (§14.1), version negotiation + GREASE (§6.1/§6.3), stateless reset sizing (§10.3.3), the 3× amplification limit (§8.1), a 128-source flood, a cancellation storm (13 checks) |
| `h3bench` | benchmark, not gated | .NET `HttpClient` over **msquic** | throughput up and down, latency percentiles, concurrency scaling — no verdict, just numbers |
| `h3interop` | live network, gated nightly at 6/8 | our own client, outbound | the client interop matrix against 8 public HTTP/3 servers — see [INTEROP.md](../INTEROP.md) |

**Why msquic.** `h3semantics` deliberately has no `ProjectReference` to Hermod. Its client is
Microsoft's QUIC stack, reached through .NET's own `HttpClient`, so every check it passes is two
independent implementations agreeing on RFC 9114 — and it puts a fourth foreign client on our
server, next to the two `curl` builds and Chromium. On a machine without QUIC support it reports
SKIP (exit code 2) rather than a green 0/0, and under `--require-all`, as CI runs it, that SKIP
fails the run.

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
Measured at pin 22768a4a: 47–66 ms per 300 000-byte round trip across three fresh runs, 150/150
uploads, no degradation. That last part was luck, as the next finding shows. The two findings
above went through two weeks of in-process tests without a ripple: both ends were ours, on moving
fake clocks. The first foreign stack to drive this server put a number on each of them within an
afternoon.

**`h3bench`, then `h3semantics`: the first large upload of a fresh connection dies.** ✅ Fixed.

About one fresh connection in five whose first request was a 300 KB POST never got an answer. The
upload completed, the server acknowledged every byte, and then both sides were silent until the
idle timeout ended the connection. GET-first connections never did this, and neither did uploads
of 140 KB or less.

The cause sat in QUIC's stream reassembly. `StreamReceiveBuffer` keyed fragments by their start
offset and let a later arrival replace an earlier one on the same key, whatever its length. A
fresh connection's first large upload bursts through slow start and loses datagrams even on
loopback, and msquic retransmits lost bytes in frames cut differently from the originals; RFC 9000
§13.3 allows exactly that. When a shorter frame landed on an offset a longer one already held, the
longer one's tail was gone. Both copies had been acknowledged, so the client never sent those bytes
again. The stream waited at the hole for good: the qlog showed every byte received, while the
stream's read position stood 80–120 KB short of its FIN and the HTTP/3 layer never saw the request
end. Reported as [Hermod#129](https://github.com/Vanaheimr/Hermod/issues/129) and fixed in
[Hermod#159](https://github.com/Vanaheimr/Hermod/pull/159): of two fragments at one offset the
longer is kept, since the bytes at an offset never change (§2.2). With a fresh connection per
trial, the stall rate went from about 1 in 5 (4/24 on Hermod master) to 0/78.

The first write-up of this finding was wrong, and it is worth saying how. It called the stall a
regression between pins 22768a4a and d2d608d2, because h3bench had been clean at the one and
failed at the other. But h3bench puts exactly one upload-first connection into each run, so the
clean pin rested on three trials, and at this rate three come out clean 42 % of the time. A
reproducer with twenty fresh connections per revision stalled 4/20 at 22768a4a. The defect is as
old as Hermod's QUIC stack, and the 111-commit bisect it seemed to call for would have chased
noise.

The gate missed it for three weeks because `h3semantics` sent its 300 KB POST on a warm
connection. It now also opens sixteen fresh connections, each uploading 300 000 bytes as its
first request. That catches a return of the defect in about 97 runs out of 100, and it fails 12/16
against Hermod master without #159.

**`h3bench` (not gated): throughput fell as concurrency rose.** 🔶 Mostly fixed.

~35 MiB/s with one `GET /big` in flight, ~10 MiB/s with 32, on loopback, where more streams have no
propagation delay or loss to hide behind. The first two explanations were wrong, and the
measurements that ruled them out are the useful part:

- *The client.* Kestrel, Microsoft's server on msquic, served the same 300 000 bytes to the same
  HttpClient at 140–190 MiB/s with 32 in flight. The client was not the limit.
- *Congestion control reacting to loss.* The server's own packet counters showed no loss at all.
- *Bufferbloat.* The congestion window had grown to ~4.7 MB, and the server's smoothed RTT sat at
  110 ms on a 0.5 ms path. Capping the window at 256 KiB brought the RTT down to 14 ms but left the
  throughput nearly where it was. Real, but a side effect.

Timing the demo host's loop settled it. At 32 in flight it was ~90 % busy, and processing one
incoming datagram cost 7.7 times as much as at one in flight. A CPU sample put ~40 % of the server
thread into acknowledgment processing. Each ACK walked every packet number of its ranges and
copied the whole sent-packet map for loss detection, roughly 2 200 steps per ACK with 2 000
packets in flight against ~120 with one request. The server fell behind its own ACKs, its RTT
estimate rose to its own queueing delay, and the client's flow-control credit arrived late in the
same queue. Fixed in [Hermod#165](https://github.com/Vanaheimr/Hermod/pull/165): an ACK now walks
what it acknowledges and loss detection stops at the largest acknowledged packet. Throughput at 32
in flight doubled, and the ladder now falls ~38 % instead of ~70 %.

What it left was a gap to Kestrel of four to five times, and slow start growing the window by
every acknowledged byte even when the window was not used. RFC 9002 §7.8 says it SHOULD NOT; that
is where the 4.7 MB came from. Fixed in [Hermod#166](https://github.com/Vanaheimr/Hermod/pull/166):
an acknowledgment no longer grows the window when the last send pass left both window and pacing
budget for another packet. Pacing alone does not count as unused, §7.8 says, so a paced bulk
transfer still grows it. With one request in flight the server's window now averages ~1.1 MB
against ~4.8 MB, and a sender of small requests keeps the window it had after the handshake.

Throughput did not move, and neither did the queue under full load. At 32 in flight the window
*is* used, so it may grow, and on loopback, with no loss, nothing ends slow start: the server's RTT
still sits near 60 ms.

Ending slow start on rising delay (HyStart++, RFC 9406) looked like the lever for that, and was
tried in [Hermod#171](https://github.com/Vanaheimr/Hermod/pull/171). It is not merged. At 32 in
flight, with the demo host built both ways and runs interleaved:

| | throughput | server sRTT p50 | window p50 | sender at its window |
|---|---|---|---|---|
| plain slow start | ~18 MiB/s | 118–133 ms | ~4.4 MB | 16–17 % of the time |
| HyStart++ | ~13 MiB/s | 55–101 ms | ~1.2 MB | 53–74 % of the time |

The machine was busy that day, so the absolute numbers are high. The comparison holds.

On a simulated bottleneck with a clean RTT, HyStart++ halves the queue at unchanged throughput.
Loopback is different: most of the RTT under load is the two endpoints' CPU, not a queue the
window builds. Rising delay then says nothing about the window, and the window HyStart++ leaves
is too small for the RTT it sits behind. The gap to Kestrel is the same CPU from the other side,
which makes it the lever for both.

**`h3semantics`: the demo host's timers ran only on silence.** ✅ Fixed.

The demo host ran its connections' timers only when `ReceiveFrom` timed out after a full second
without a datagram, from any client. These were the probe timeout, loss detection, the idle
timeout, the end of closing/draining, and handler tasks finishing in the background. Every
harness kept the server talking, so nothing noticed. The new check takes the client away instead.
A UDP relay forwards a `GET /big` until 40 datagrams of the response are through, then drops
everything in both directions for 1.5 s. Whatever the server sends in that time, it sends on its
own timer. The first 50 ms do not count, because the server may still be answering what reached
it just before the cut.

Against the old loop, a quiet server's first datagram came after 1 083 ms. While a second client
kept the server busy, it sent nothing in the whole 1.5 s, because a talking neighbour means the
receive never times out. That second case is the one that pins the fix: a shorter receive
timeout alone would pass the first check and still fail the second.

The timers now run every 5 ms: through the receive timeout on a quiet socket, and through a clock
comparison after each datagram under load. The server now probes after 60–140 ms in both cases.
Polling the socket before each receive would have cost a system call per datagram. Measured on
the same 64 responses, that is ~6 % more server CPU, so the loop does not poll. An interleaved
A/B of the concurrency ladder showed no throughput difference between the old loop and the new
one. The idle server costs 0.16 % of one core.

Hermod's own `Http3Server` has the milder form of the same pattern, found by reading the code,
not by measurement. It runs its timers only when no datagram arrives within its 20 ms tick, and
otherwise touches only connections that just received something. So a silent connection's
probe timeout waits for as long as another connection keeps it busy. No harness here runs
against it. It is listed in PLAN.md.

## Benchmarks (h3bench)

```bash
dotnet run --project samples/H3Server -- 4433
```
```bash
dotnet run --project tests/h3bench --configuration Release
```

Everything else in this repository has a number behind it — 738 in-process tests, 42/42 harness checks,
8 foreign stacks, Chrome and Edge 8/8. Performance had none, which made "readable rather than fast"
an assumption rather than a finding. Loopback measures our packet handling, framing and crypto, not
a network, and the msquic client's cost sits inside every figure: comparing two runs of this file is
meaningful, comparing it to a datacentre benchmark is not.

Baseline on a 16-core Windows 11 machine, .NET 10.0.403, measured 2026-10-29 at Hermod pin
cc9bdd2a, which carries the reassembly fix (Hermod#159) and the ACK-cost fix (Hermod#165). Median
of five runs; a sixth, taken while the machine was visibly busy (p50 latency 2 ms), is left out:

| Measurement | Result | 2026-10-04, pin 22768a4a |
|---|---|---|
| `GET /big` (300 000 B), sequential | ~37 MiB/s, ~7.7 ms/request | ~30 MiB/s, ~9.5 ms |
| `POST /echo` (300 000 B, echoed) | ~9 MiB/s, 53–68 ms/round trip, one run 102 ms | 47–66 ms |
| `GET /` latency, 90 requests | p50 0.31 ms · p90 0.38 ms · p99 7.8 ms | p50 0.35 · p90 0.43 · p99 7.7 |
| `GET /` sustained | ~2 475 requests/s | ~2 250 |
| `GET /big`, 1 → 32 in flight | ~45 → ~28 MiB/s | ~35 → ~10 |

The last row is the finding above, now mostly fixed. The older column's upload range was luck as
much as measurement: those runs did not happen to draw a connection that hit Hermod#129.

Not re-measured at pin 14c9701c (Hermod#166). The machine was busy with other work that day, and
both pins measured about half these figures. An interleaved A/B of the two pins, four ladders
each, showed no difference between them.
