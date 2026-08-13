# HTTP/3 Conformance & Interoperability Test Suite

[![CI](https://github.com/Vanaheimr/HTTP3ConformanceTests/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/HTTP3ConformanceTests/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/HTTP3ConformanceTests/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/HTTP3ConformanceTests/actions/workflows/nightly.yml)

The **conformance and interoperability test drivers** for the from-scratch HTTP/3 stack that lives
in the Vanaheimr **Hermod** library — QUIC + TLS 1.3 + HTTP/3 in pure C# on .NET 10, straight on UDP
sockets, no large dependencies beyond the BCL. Hermod is pulled in here as a git submodule under
`libs/`; this repository is what drives it, and what has to answer the only question that matters
about a hand-written protocol stack: **does it actually interoperate with implementations nobody
here wrote?**

Everything below is repeatable from a clean checkout with the command next to it.

| Driver | What it establishes | Result |
|---|---|---|
| `pwsh tests/run-tests.ps1` | the gate: two harnesses against the live demo host over real UDP | **37/38 checks** |
| ├ [`tests/h3semantics`](tests/h3semantics) | RFC 9114 semantics, driven by **msquic** through .NET's `HttpClient` — a foreign stack on the client side | 24/25 checks |
| └ [`tests/h3attack`](tests/h3attack) | hand-built hostile datagrams: noise, undersized Initials, version negotiation, stateless reset, amplification, a 128-source flood | 13/13 checks |
| `dotnet run --project tests/h3interop` | our client against **8 public QUIC stacks** — quiche, nginx, Google, mvfst, lsquic, msquic, quic-go, Akamai — full chain + hostname validation, no `-k` | **8/8** reachable |
| `pwsh tools/browser-interop.ps1 -Browser chrome` | **Chrome 150 / Edge 150** headless, incl. WebTransport and the post-quantum hybrid | **8/8** checks |
| `curl --http3-only -k https://127.0.0.1:4433/` | **ngtcp2/LibreSSL** and **OpenSSL-QUIC** against our server — GET, POST, 300 KB, 103 + trailers | see [INTEROP.md](INTEROP.md) |
| `dotnet test libs/Hermod/HermodTests` | the in-process suite that ships with the stack: RFC vectors, "evil" raw-QUIC peers, a seeded lossy link | **247 tests** |
| `dotnet run --project tests/h3bench` | throughput, latency percentiles, concurrency scaling | numbers, no verdict |

On the other side of those rows sits code nobody here wrote: eight public QUIC stacks, two
independent `curl` builds, Chromium's QUICHE in two browsers, and msquic driving our own server.
That is the point of the table. The 247 in-process tests are the more thorough half of the coverage
and they gate every push — but they cannot disagree with us, because both ends of every one of them
are our own code, sharing one reading of the RFCs and one set of bugs.

### What the drivers have found

Two things, both from the out-of-process harnesses, and neither reachable from in-process tests:

- **A connection stalls after exactly 100 requests.** `MAX_STREAMS` is parsed and logged but never
  sent, so `initial_max_streams_bidi` is the lifetime budget of every connection (RFC 9000 §4.6).
  A browser tab reaches that on one page. Pinned by `h3semantics`; it is the 1 in 37/38.
- **Large uploads are slow and eventually fatal.** 300 000 bytes down takes ~11 ms; the same
  300 000 bytes up takes ~130 ms, degrading to ~830 ms until the connection is lost to the idle
  timeout mid-upload. Measured by `h3bench`.

Details in [tests/README.md](tests/README.md). The interop evidence and how to repeat it is in
[INTEROP.md](INTEROP.md); the implementation history — phases, milestones, crypto roadmap — is in
[PLAN.md](PLAN.md), and the stack's own reference lives next to the code in
`libs/Hermod/Hermod/QUIC/` and `libs/Hermod/Hermod/HTTP3/`.

## RFC coverage

What the stack implements, and therefore what there is to conform to. The stack itself now lives in
Hermod — this table is the map from RFC to evidence, not a build log; the chronology is in
[PLAN.md](PLAN.md).

| Ref | What is covered | State |
|-------|---------|--------|
| 0 | Setup, VarInt, buffer reader/writer, test scaffolding | ✅ done |
| 1 | Initial crypto (HKDF, packet/header protection, Retry) — RFC 9001 App. A byte-exact | ✅ done |
| 1b | QUIC packet formats (long/short header, connection ID, packet numbers) — RFC 9000 §17 | ✅ done |
| 1c | QUIC frames (PADDING, PING, ACK, CRYPTO, STREAM, CONNECTION_CLOSE, …) — RFC 9000 §19 | ✅ done |
| 2 | TLS 1.3 handshake: ClientHello, ServerHello, ECDHE (P-256), transport parameters | ✅ done |
| 2b | TLS key schedule (verified against RFC 8448) → handshake packets decrypted live | ✅ done |
| 3a | Sending our own Finished, ACKs, 1-RTT keys — **handshake fully completed** | ✅ done |
| 3b | Reusable `QuicClientConnection` + `TlsClientHandshake` engine | ✅ done |
| **M1** | **Full QUIC/TLS 1.3 handshake against cloudflare-quic.com — HANDSHAKE_DONE received** | ✅ **reached** |
| 4 | Streams & flow control — server HTTP/3 streams reassembled | ✅ done |
| 6 | QPACK (static table + Huffman + literals) — RFC vectors verified | ✅ done |
| 7 | HTTP/3 (control/QPACK streams, SETTINGS, HEADERS/DATA) | ✅ done |
| **M2** | **Real `GET https://cloudflare-quic.com/` — status 200 + 126 KB HTML** | ✅ **reached** |
| 4-FC | Receive-side flow-control updates (`MAX_STREAM_DATA`/`MAX_DATA`) | ✅ done |
| 5 | Loss recovery (RFC 9002): RTT, loss detection, PTO, NewReno, retransmission | ✅ done |
| 8-S | HTTP/3 **server** (TLS server handshake, self-signed cert, QUIC/HTTP-3 server) | ✅ done |
| **M3** | **Our own server: the `H3Get` client fetches status 200 + HTML over real localhost UDP** | ✅ **reached** |
| 8 | Robustness: VN, Retry, close/draining, idle/keep-alive, key lifecycle & key update, 0-RTT + resumption, CID rotation, stateless reset, migration, RESET_STREAM/STOP_SENDING, PQ hybrid, ML-DSA certificates | ✅ core complete |
| 7+ | **RFC 9114 feature audit**: request bodies, cancellation, frame state machine + H3 error codes, GOAWAY, trailers/1xx, MAX_FIELD_SECTION_SIZE, malformed validation | ✅ **complete** |
| 9218 | **Priorities**: priority header + PRIORITY_UPDATE, §10 scheduler (urgency/incremental) | ✅ done |
| 9220 | **WebSockets over HTTP/3**: Extended CONNECT (RFC 8441) + tunnel + RFC 6455 framing (reused from Hermod) | ✅ done |
| 9297/9221 | **HTTP datagrams** over QUIC DATAGRAM frames | ✅ done |
| webtrans | **WebTransport over HTTP/3** (draft-13): sessions, uni/bidi streams, datagrams, flow-control capsules, protocol negotiation (`WT-Available-Protocols`/`WT-Protocol`) | ✅ done |
| reset-at | **RESET_STREAM_AT** (draft-ietf-quic-reliable-stream-reset): stream reset with guaranteed partial delivery (`reset_stream_at` TP + frame 0x24) | ✅ done |
| async | **async API**: `Http3Client`/`Http3Server` — Task facades with their own UDP socket + background pump (`ConnectAsync`/`GetAsync`/`SendAsync`, `Http3RequestException`, CID demux incl. migration) | ✅ done |
| curl | **`curl --http3` interop (server side)**: ngtcp2/LibreSSL (Windows curl 8.21) **and** OpenSSL-QUIC (WSL/Debian curl 8.14) — GET/POST/300 KB/103+trailers | ✅ done |
| 8+ | **Transport-error matrix complete**: connection-level FLOW_CONTROL_ERROR, TRANSPORT_PARAMETER_ERROR (§7.3 authentication + §7.4/§18.2 value ranges), §10.2.3 close delivery, parser fuzzer | ✅ done |
| 9 | **Performance**: zero-alloc hot paths (`ByteQueue`, 300 KB download 51→7 MiB), UDP batching (GSO via `UdpBatchSender`), window auto-tuning (`ReceiveWindowTuner`, BDP) | ✅ done |
| interop | **Client interop against 8 foreign QUIC stacks**: quiche, nginx, Google, mvfst, lsquic, msquic, quic-go, Akamai — each 2xx/3xx with full cert validation | ✅ done |
| browser | **Browser interop (server side)**: Chrome 150 / Edge 150 headless, 8/8 checks incl. WebTransport and the PQ hybrid — `tools/browser-interop.ps1` | ✅ done |
| harness | **Out-of-process harnesses** (`tests/`): `h3semantics` drives our server with **msquic** — the first foreign client to do so besides `curl` and the browsers — and `h3attack` with hand-built hostile datagrams; `pwsh tests/run-tests.ps1` gives one verdict | 🔶 37/38 |
| bench | **`h3bench`**: throughput, latency percentiles and concurrency scaling against the demo host — the first reproducible performance numbers this repository has | ✅ done |

### Per-area detail

The sections below record what each area implements and which live check exercised it — the
"**Live:**" lines are the reproducible part. They describe code that now lives in Hermod; for the
API and the internals, read the READMEs next to it.

### X25519 & HelloRetryRequest (interop)

- `X25519KeyExchange` (BouncyCastle, encapsulated behind `IKeyExchange` — the only external crypto dep);
  the client offers X25519 + P-256, the server picks from the key shares
- **HelloRetryRequest** (RFC 8446 §4.1.4) on the client **and** server side, including the synthetic
  `message_hash` transcript handling — tested in-process (client offers only P-256, server demands
  X25519 → HRR → completion with X25519)
- **Live:** against `cloudflare-quic.com`, **X25519** is negotiated (`Handshake completed (group X25519)`)
- **Client interop matrix (live, full cert validation without `-k`):** the client fetches status 2xx/3xx
  from **8 independent QUIC stacks** — quiche (Cloudflare), nginx, Google, mvfst (Meta), lsquic
  (LiteSpeed), **msquic** (Microsoft, `outlook.office.com` — P-256 + AES-256 + RSA), quic-go (Caddy)
  and Akamai (AES-256). Covers both KEX groups (X25519 + P-256), both suites (AES-128/256-GCM) and
  both cert types (ECDSA + RSA-PSS) live. Full table + one-command repeat: **[INTEROP.md](INTEROP.md)**
  (`dotnet run --project tests/h3interop`).
- **X448** (RFC 7748, Curve448, named group 0x001e): key-exchange primitive from BouncyCastle
  (`X448KeyExchange`, encapsulated like X25519), 56-byte key/secret. RFC 7748 §5.2 byte-exact; the named
  groups are threaded through the whole API (`keyExchangeGroups`/`preferredGroups`). Live over UDP:
  `H3Server --x448` + `H3Get --x448 -k` → group X448, status 200
- **X25519MLKEM768** (post-quantum hybrid, named group 0x11EC, draft-ietf-tls-ecdhe-mlkem): combines
  **ML-KEM-768 from the BCL** (`MLKem`, .NET 10 native) with X25519 (BouncyCastle). A KEM is asymmetric,
  so `IKeyExchange` has an `Encapsulate` method (server encapsulates, client decapsulates). Shares/secret:
  ek(1184)‖x25519 / ct(1088)‖x25519 / ss_mlkem‖ss_x25519 — ML-KEM first. **Byte-exact interop live against
  cloudflare-quic.com** (`H3Get --mlkem` → group X25519MlKem768, full chain, status 200, 126 KB)
- **Ed25519** (RFC 8032, `SignatureScheme` 0x0807): signature primitive from BouncyCastle (`Ed25519Signature`,
  encapsulated like X25519) — the client verifies the CertificateVerify signature (PureEdDSA, no pre-hash),
  `ServerCertificate` generates a self-signed Ed25519 certificate on demand. RFC 8032 §7.1 byte-exact;
  live over UDP: `H3Server --ed25519` + `H3Get -k` → signature verified, status 200
- **Ed448** (RFC 8032, `SignatureScheme` 0x0808, edwards448/SHAKE256): analogously from BouncyCastle
  (`Ed448Signature`), PureEdDSA with empty context, 57-byte key / 114-byte signature; `ServerCertificate`
  generates an Ed448 certificate on demand. RFC 8032 §7.4 byte-exact; live over UDP: `H3Server --ed448` +
  `H3Get -k` → signature verified, status 200
- **ML-DSA** (FIPS 204, draft-ietf-tls-mldsa, `SignatureScheme` mldsa44/65/87 = 0x0904–0x0906):
  post-quantum signatures, completely **BCL-native** (.NET 10 `MLDsa` + `CertificateRequest`) — pure
  signature without pre-hash, empty FIPS 204 context; the client additionally checks that the
  parameter strength of the certificate key (id-ML-DSA-44/65/87) matches the scheme.
  `ServerCertificate.CreateSelfSignedMLDsa()`. Live over UDP: `H3Server --mldsa` + `H3Get -k` →
  status 200 — and **fully post-quantum** with `--mldsa --mlkem` (X25519MLKEM768 KEX + ML-DSA-65 signature)

### HTTP/3 server (M3)

- `ServerCertificate` — self-signed ECDSA P-256 via `CertificateRequest` (for `curl -k` / tests)
- `TlsServerHandshake` — ServerHello/EncryptedExtensions/Certificate/**CertificateVerify (signed)**/
  Finished, verifies the client Finished. Verified in-process against the client handshake (matching secrets)
- `QuicServerConnection` — server role (Initial keys from the client DCID, HANDSHAKE_DONE),
  `Http3ServerConnection` — accepts requests, invokes a handler, sends HEADERS + DATA
- Client and server share the transport logic via the `QuicEndpoint` base class; the two connection
  classes are thin subclasses with role hooks (key direction/stream perspective via `IsServer`)
- **M3 live:** `dotnet run --project samples/H3Server` + `dotnet run --project samples/H3Get -- localhost / --port=4433 -k`
  → status 200 + our own HTML page over real UDP (both ends from scratch)
- **`curl --http3` interop:** the server side passes against two independent foreign HTTP/3 stacks —
  the official Windows curl 8.21 (**ngtcp2 + nghttp3 + LibreSSL**) and the Debian curl 8.14 under
  **WSL** (**OpenSSL-3.5-QUIC** + nghttp3, across the WSL2 NAT boundary): handshake, `GET /` (200),
  `POST /echo` (byte-exact echo), `GET /big` (300 000 B), `GET /hints` (103 Early Hints + final
  200 + trailers), clean closes. Example: `curl --http3-only -k https://127.0.0.1:4433/`
- **Browser interop:** `GET /browser` serves a page whose JS runs the whole battery and posts its
  verdict to `/report`, which the server prints — so the server log is the record and a headless run
  needs no DOM scraping. Chrome 150 and Edge 150 both report 8/8, including WebTransport (session via
  `serverCertificateHashes`, datagram + bidi + uni echo) and, with `--mlkem`, the PQ hybrid
  `X25519MLKEM768`. One command: `pwsh tools/browser-interop.ps1 -Browser chrome`.
  Details and the two required browser flags: **[INTEROP.md](INTEROP.md)**

### Certificate validation (client)

- **CertificateVerify signature** (RFC 8446 §4.4.3) over the transcript hash with the public key of
  the leaf certificate — **always** verified (ECDSA P-256/P-384, RSA-PSS). This is the actual
  cryptographic MITM defence: it binds the presented certificate to exactly this handshake.
- **Trust policy** separate from that, via `CertificateValidationOptions`: chain building up to a
  trusted root (`X509Chain`), hostname (`X509Certificate2.MatchesHostname`) and validity period.
  `Default` = full validation against the system roots; `Insecure` = like `curl -k` (signature only);
  `CustomTrustRoots` = trust a specific test certificate.
- **Live:** GET against `cloudflare-quic.com` passes with **full** chain validation
  (`CN=cloudflare-quic.com`, chain up to a Windows system root, hostname match). The local
  self-signed H3Server is correctly **rejected** without `-k`, accepted with `-k`.

### Flow control & loss recovery (phases 4/5)

- **Flow control (receive):** `QuicClientConnection` tracks the windows and sends
  `MAX_STREAM_DATA`/`MAX_DATA` as soon as the credit falls below half the window — with `--small`
  the sample loads the 126 KB page even through a 48 KB connection window.
- **Loss recovery (RFC 9002):** `RttEstimator`, `NewRenoCongestionControl`, `LossRecovery`
  (sent-packet tracking, packet/time threshold, PTO). Lost CRYPTO/STREAM frames are resent.
  `dotnet run --project samples/H3Get -- --loss=10` survives the loss: handshake + GET get
  through despite ~17 dropped datagrams.
- **ECN (RFC 9000 §13.4 / RFC 9002 §7.3):** the receiver counts the ECN codepoints (ECT0/ECT1/CE) per
  packet-number space and reports them in the ACK frame (type 0x03); the sender treats an increased
  CE counter like a loss and halves the congestion window (once per recovery period). The codepoint
  comes in via `ProcessDatagram(dg, ecn)`. Verified in-process (counting/reporting, CE reaction,
  end-to-end cwnd decrease). The actual IP marking (setting ECT/reading CE) is beyond BCL UDP
  sockets (especially on Windows) — pure transport layer, the protocol logic is complete.
- **cwnd enforcement & pacing (RFC 9002 §7/§7.7):** new stream data is limited by
  `min(cwnd − bytes_in_flight, pacing budget)`; the `Pacer` (token bucket, rate
  `1.25·cwnd/smoothed_rtt`, burst cap ≈ initial window) spreads it over time; pure ACKs and
  PTO probes remain exempt. The 1-RTT send path emits multiple **MTU-sized** packets per call.
  A 150 KB in-process transfer proves byte-exact, MTU-conformant transmission over the paced path.
- **Persistent congestion (RFC 9002 §7.6):** during a blackout period (two ack-eliciting packets
  lost, nothing acknowledged in between, spacing > PC duration `≈ PTO·3`) the window collapses to
  `kMinimumWindow` and slow start restarts — only takes effect after the first RTT sample.
- **Idle timeout (RFC 9000 §10.1):** `IdleTimeout` negotiates `min(local, peer)` (0 = disabled),
  effectively raises it to at least `3·PTO` and restarts the timer on successful receive or when
  sending an ack-eliciting packet. When it expires, the connection is closed silently. The `H3Server`
  reaps inactive connections — `dotnet run --project samples/H3Server -- 4433 --idle=3000` closes
  a connection ~3 s after the last packet (log: "closed after idle timeout").
- **Keep-alive via PING (RFC 9000 §10.1.2):** if `KeepAliveInterval` is set, the connection schedules
  an ack-eliciting PING after the corresponding inactivity, resetting the idle timeout on both sides.
  **Live:** `H3Get … --hold=6` against `H3Server … --idle=3000` — the connection stays open idle for
  6 s where it would be reaped after 3 s without keep-alive.

### Version negotiation & Retry (RFC 9000 §6/§8.1)

- **Version negotiation:** the server answers an unsupported version with a
  `VersionNegotiationPacket` (version field 0, listed versions, DCID/SCID swapped). Anti-amplification
  (§6.1/§14.1): no VN for datagrams < 1200 B. As GREASE (§6.3) a reserved version matching the pattern
  `0x?a?a?a?a` is included, probing client robustness and preventing ossification. The client detects
  VN, applies the §6.2 discard rules, ignores the reserved version and otherwise reports
  `VersionNegotiationReceived` + `OfferedVersions`.
- **Retry / address validation:** with `--retry` the `H3Server` responds to the first Initial with a
  `RetryPacket` carrying a token and 16-byte integrity tag (RFC 9001 §5.8). The client verifies the tag
  against its original DCID, **re-derives** the Initial keys from the Retry SCID (RFC 9001 §5.2),
  echoes the token in the next Initial and completes the handshake. **Live:**
  `dotnet run --project samples/H3Server -- 4433 --retry` + `H3Get … -k` → "Handshake completed …
  after Retry (address validation)" + status 200.
- **Stateless Retry** (RFC 9000 §8.1.2/§8.1.4) — the form that actually helps under load. `--retry`
  creates the connection object first and only then sends the Retry, so every spoofed Initial still
  costs state. With `--stateless-retry` (or `Http3Server(..., addressValidation: new
  RetryTokenGenerator())`) the decision is made from the cleartext header alone: no token ⇒ Retry,
  valid token ⇒ connection, bad token ⇒ INVALID_TOKEN in an Initial. The token — AES-256-GCM over
  `kind ‖ issued ‖ ODCID ‖ Retry-SCID`, with the client address and port as associated data — *is*
  the state, so nothing is remembered between the two round trips. Same flood of 128 distinct
  sources: dozens of connections without it, zero with it. **Live:** `curl --http3` completes
  through the Retry.

- **Client certificates / mutual TLS** (RFC 8446 §4.3.2): the server asks with a CertificateRequest
  after EncryptedExtensions (never on a PSK handshake — §4.3.2 MUST NOT); the client answers at the
  end of its flight with Certificate + CertificateVerify signed under the *client* context string,
  and its Finished covers both. `ClientCertificateMode.Require` rejects an anonymous client with
  `certificate_required`; `Request` lets it in unauthenticated and hands the application the verdict
  via `ClientAuthentication`. **Live:**
  `dotnet run --project samples/H3Server -- 4433 --mtls=ca.pem` +
  `curl --http3 --cert client.pem --key client.key -k https://localhost:4433/` → 200, while the same
  curl without a certificate is refused and the server keeps serving everyone else.

### Connection close & draining (RFC 9000 §10.2)

- `Close(TransportError, reason)` sends a CONNECTION_CLOSE and puts the connection into the
  **closing** state (only CONNECTION_CLOSE from then on, re-sent for every incoming packet). Receiving
  a CONNECTION_CLOSE leads to the **draining** state (nothing is sent anymore, `PeerCloseFrame`
  recorded); after `3·PTO` follows **closed**. States visible via `IsClosing`/`IsDraining`/`IsClosed`.
- **Live:** `H3Get` closes down properly after the GET ("CONNECTION_CLOSE, NO_ERROR"); the `H3Server`
  logs "peer … closed the connection" and removes the draining connection.

### Key lifecycle (RFC 9001 §4.9)

- **Discarding after the handshake:** Initial keys are discarded as soon as the client sends a
  Handshake packet or the server processes one (§4.9.1); Handshake keys once the handshake is
  confirmed (§4.9.2). `DiscardKeys` clears keys, pending CRYPTO/retransmits and the loss-recovery
  space (RFC 9002 §6.4). Fixes a bug where a post-handshake PTO wrongly probed the Initial space and
  resent the ClientHello as a 1200-byte Initial.
- **Handshake confirmation (§4.1.2):** the server confirms at completion; the client at
  HANDSHAKE_DONE **or** — additionally (RFC-legitimate) — as soon as one of its **1-RTT packets is
  acknowledged**. This way the Handshake keys are discarded (earlier) even when HANDSHAKE_DONE is
  lost — verified in-process (confirmation solely via 1-RTT ACK with HANDSHAKE_DONE suppressed).
- **No reordering window for Handshake keys (§4.9.2):** the Handshake keys are discarded
  **immediately** on confirmation — unlike 0-RTT keys, for which §4.9.3 explicitly allows the server
  a short retention (~3×PTO) against reordering. This asymmetry is intentional: after mutual
  confirmation, a late reordered Handshake packet would only carry information already known, and
  keeping keys longer would only widen the attack window. (The "keep briefly" of previous read keys
  applies exclusively to the 1-RTT key update per §6.)
- **Client 0-RTT keys (§4.9.3):** the client discards its 0-RTT key set as soon as the 1-RTT keys are
  installed — it sends no 0-RTT packets after that and never receives any itself. There is **no**
  reordering window for this (unlike on the server): the client has no 0-RTT read path, and lost
  0-RTT data is retransmitted over 1-RTT — the keys have "no use after that moment".
- **Server 0-RTT read keys (§4.9.3):** the server keeps them briefly after the **first received
  1-RTT packet** (so reordered 0-RTT packets remain decryptable without 1-RTT retransmission) and then
  discards them "within a short time" — RECOMMENDED **3×PTO**, purely time-driven (even without
  further traffic). **Earlier**, as soon as the packet numbers from 0 are gap-free: then provably all
  0-RTT packets have arrived ("keeping track of missing packet numbers") and the keys are discarded
  immediately instead of waiting out the deadline. If the connection ends earlier, `Dispose()`
  releases the 0-RTT read keys (along with all other keys).

### Key update (RFC 9001 §6)

- `TrafficKeys.Next` derives the next generation (`secret_<n+1> = HKDF-Expand-Label(secret_<n>,
  "quic ku", …)` → new key/IV, **HP key unchanged**). `PacketProtection.RemoveHeaderProtection`
  separates header from packet protection so the **key-phase bit** can be read before key selection.
- `InitiateKeyUpdate()` rotates the send keys and flips the phase; a received flipped bit rotates
  read (and possibly send) keys; previous read keys are kept briefly for reordered packets.
- **Live:** `dotnet run --project samples/H3Get -- --key-update` fetches the page, rotates the keys and
  repeats the GET **under the new keys** — against `cloudflare-quic.com` status 200 both times.

### Session resumption / PSK (RFC 8446 §2.2/§4.6.1) + 0-RTT (RFC 9001 §4)

- After the handshake the server issues a **NewSessionTicket** (stateful `ServerResumptionCache`);
  the client derives the resumption PSK from it (`resumption_master_secret` → `HKDF-Expand-Label(…,
  "resumption", nonce)`) and stores it as a `ResumptionTicket`.
- Resumption sends `pre_shared_key` (as the **last** extension) with a **binder** — `HMAC(finished_key(
  binder_key), transcript hash(ClientHello up to just before the binder list))`, the classic truncation
  boundary from RFC 8446 §4.2.11.2 — plus `psk_key_exchange_modes` (which is **always** sent,
  otherwise the server issues no tickets). The server verifies the binder and resumes **without
  Certificate/CertificateVerify**.
- **Live resumption:** `H3Get --resume` → first a GET, then a second connection via PSK. Against
  `cloudflare-quic.com`, Cloudflare delivers 2 real tickets, accepts our binder byte-exactly (**"PSK
  accepted, no certificate"**) and answers the second GET with status 200; likewise against `H3Server`
  over UDP.
- **0-RTT (early data):** if the ticket allows 0-RTT, the client sends the `early_data` extension and
  derives the `client_early_traffic_secret`. The HTTP/3 request is sent **before** handshake
  completion as a **0-RTT packet** (long header 0x01, its own key set in the application PN space);
  the server confirms early_data in the EncryptedExtensions and processes the request immediately.
  **Live:** `H3Get --zerortt` against `cloudflare-quic.com` → **"0-RTT ACCEPTED"**, 126 KB, status 200
  (no round trip before the request); likewise against `H3Server` over UDP.
- **0-RTT rejection → 1-RTT retry** (RFC 9001 §4.6.2): if the server rejects early_data, normal loss
  recovery already applies thanks to the shared application PN space; additionally the client
  **proactively** moves the 0-RTT frames into the 1-RTT retransmit queue on detected rejection
  (without PTO delay, without double-sending). The request thus gets through even on rejection —
  verified in-process (server rejects ⇒ status 200 over 1-RTT). The **Handshake key discard** also
  stays correct on this path: confirmation via 1-RTT ACK (§4.1.2) counts only real 1-RTT packets
  (never a 0-RTT packet, although both share the same PN space), so a 0-RTT ACK never confirms the
  handshake too early — verified (0-RTT rejected + HANDSHAKE_DONE suppressed ⇒ confirmation only via
  the 1-RTT ACK, then Handshake keys gone).

### Connection-ID rotation (RFC 9000 §5.1)

- `ConnectionIdManager` manages the connection IDs we issued (peer → DCID) and those offered by the
  peer (us → DCID) along with sequence numbers. `IssueConnectionId()` sends NEW_CONNECTION_ID
  (respecting `active_connection_id_limit`); `RotateDestinationConnectionId()` switches the DCID and
  retires the old one via RETIRE_CONNECTION_ID. "Retire Prior To" and incoming RETIRE are handled;
  packets to a local CID that was never (or no longer is) issued are dropped.
- **Live over UDP:** the `H3Server` offers a spare CID after the handshake; `H3Get … --rotate-cid`
  switches its DCID to it and repeats the GET **under the new connection ID** (status 200).

### Stateless reset (RFC 9000 §10.3)

- **Receive:** the peer's stateless-reset tokens (from NEW_CONNECTION_ID + the
  `stateless_reset_token` TP) are stored. A non-processable short-header datagram whose **last 16
  bytes** match a known token (constant-time) is recognised as a stateless reset and ends the
  connection (`StatelessResetReceived` → draining).
- **Send:** the server derives its tokens from the CID — `StatelessResetTokenGenerator` =
  `HMAC-SHA256(secret, CID)[0..16]` (§10.3.1) — so they remain recomputable after state loss.
  The demux (`H3Server`) answers a 1-RTT packet for an **unknown** DCID with
  `StatelessReset.BuildResponse`: compute the token from the DCID, build a reset **smaller** than the
  triggering packet (loop avoidance §10.3.3), only for short headers above a minimum size. Tested
  in-process end-to-end (stateless responder with shared secret → reset which the client recognises).
- **Persisted secret:** the `H3Server` stores the secret in a file (`--secret-file=`, default next to
  the exe) and loads it at startup — so it stays identical across **restarts** (verified: identical
  bytes, startup message "loaded — survives restarts"), which lets a freshly restarted server send
  valid, client-recognisable resets for connections established before the restart. The demux only
  opens new connections for genuine **Initial** packets; short header to unknown CID ⇒ reset, other
  long headers ⇒ dropped.

### Transport-error matrix (RFC 9000 §11)

- Protocol violations by the peer are answered with a CONNECTION_CLOSE carrying the appropriate error
  code instead of being silently ignored or crashing: **FRAME_ENCODING_ERROR** (broken/unknown frame),
  **STREAM_LIMIT_ERROR** (stream beyond the granted limit), **FLOW_CONTROL_ERROR** and
  **FINAL_SIZE_ERROR** (wired up from the `StreamReceiveBuffer`). After the first violation no
  further frames of the packet are processed.
- At the same time **PATH_CHALLENGE/PATH_RESPONSE** (RFC 9000 §19.17/§19.18) are added and answered —
  with that the parser covers all v1 frames and "unknown frame = fatal" doesn't break real servers
  (confirmed live against `cloudflare-quic.com`). Tested end-to-end (among others STREAM_LIMIT_ERROR).

### Connection migration (RFC 9000 §8.2/§9)

- **Path validation:** `InitiatePathValidation()` sends a PATH_CHALLENGE with 8 random bytes; a
  matching PATH_RESPONSE sets `PathValidated` (deadline 3·PTO). PATH_CHALLENGE is answered. Via
  `OwnsConnectionId`, connections can be identified by connection ID (instead of by address).
- **Live over UDP:** the `H3Server` demultiplexes via the connection ID; `H3Get … --migrate` switches
  the local UDP port and fetches a second GET — the server detects the migration (log: "connection
  migration: … → …"), validates the new path and answers the GET **over the new path** (status 200).
  The connection survives the address change. Tested in-process (client/server-initiated + expiry timeout).

### Anti-amplification limit (RFC 9000 §8.1)

- Before address validation the **server** sends at most **3× as many bytes as it has received** —
  protection against amplification via spoofed source addresses. If the budget doesn't suffice, the
  CRYPTO stays persistently buffered and goes out once more has been received. The address counts as
  validated at the first decrypted **Handshake packet** (the peer owns our handshake keys) or at a
  valid **Retry token**; the client is unrestricted by construction. Tested via the invariant
  `sent ≤ 3×received`; live, our own server reaches the goal under the limit.

### HTTP/3 (phase 7, RFC 9114 — `Http3`)

- `Http3Frames` (DATA/HEADERS/SETTINGS, incremental parsing), `Http3Request`/`Http3Response`
- `Http3ClientConnection` on top of `QuicClientConnection`: opens the control stream (+ SETTINGS) and
  QPACK encoder/decoder streams, sends requests as a QPACK-encoded HEADERS frame on a bidirectional
  stream, reassembles the response (HEADERS → QPACK decode, DATA → body)
- **Request bodies (RFC 9114 §4.1):** `Http3Request.Body`/`Http3Request.Post(...)` — the body follows
  the HEADERS frame as a DATA frame (automatic `content-length`, §4.1.2); the server collects DATA
  frames and only answers the message once it is complete (FIN). Tested via POST echo + 120 KB upload
  (SHA-256-verified, the first time the client send path is under load);
  **live:** `H3Get --post=<text>` — echo against our own `H3Server` (`POST /echo`) over UDP and
  POST against `cloudflare-quic.com` (status 200)
- **Request cancellation (RFC 9114 §4.1.1) + RESET_STREAM/STOP_SENDING (RFC 9000 §19.4/§19.5):**
  `CancelRequest` aborts send and read side with `H3_REQUEST_CANCELLED`; the QUIC layer delivers both
  frames reliably (loss recovery), validates final size (§4.5) and stream states
  (STREAM_STATE_ERROR) and automatically answers STOP_SENDING with RESET_STREAM carrying the copied
  error code (§3.5 MUST); the server detects client aborts (H3_REQUEST_REJECTED/CANCELLED).
  H3 error codes (§8.1) as `Http3Error`. **Live:** `H3Get --cancel` against `cloudflare-quic.com` —
  abort mid-download, Cloudflare resets with `0x10c`, a second GET over the **same** connection
  delivers status 200
- **Frame/stream state machine (RFC 9114 §4.1/§6.2/§7.2):** protocol violations by the peer are
  answered with CONNECTION_CLOSE **type 0x1d** and the correct H3 error code —
  H3_MISSING_SETTINGS (first control frame ≠ SETTINGS), H3_FRAME_UNEXPECTED (second SETTINGS,
  DATA before HEADERS, frames after trailers, reserved HTTP/2 types, PUSH_PROMISE from the client, …),
  H3_STREAM_CREATION_ERROR (duplicate critical streams, client push stream), H3_CLOSED_CRITICAL_STREAM
  (control/QPACK stream ends), H3_SETTINGS_ERROR (reserved/duplicate setting IDs), H3_FRAME_ERROR
  (layout violations, truncated final frame), H3_ID_ERROR (push without MAX_PUSH_ID, GOAWAY with
  wrong ID). Grease frames/settings are tolerated and sent ourselves (§7.2.4.1 SHOULD);
  14 tests with deliberately "evil" raw-QUIC peers in both directions, live interop unchanged
- **WebSockets over HTTP/3 (RFC 9220 / RFC 8441 / RFC 6455):** Extended CONNECT with the
  `:protocol` pseudo-header, gated via `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08); after the 2xx
  acceptance the request stream becomes a byte tunnel (`Http3Tunnel`, bytes in DATA frames per
  RFC 9114 §4.4; FIN ≙ TCP close, reset ≙ `H3_REQUEST_CANCELLED`). The **RFC 6455 framing is reused
  from Hermod's HTTP/2 WebSocket** (byte-identical copies, only the namespace swapped — it is written
  transport-agnostically against the 2-method tunnel interface, incl. masking, UTF-8 validation,
  permessage-deflate, close handshake). Unknown `:protocol` ⇒ 501.
  **Live over UDP:** `H3Get --websocket` — CONNECT 200 → text echo → close handshake
- **WebTransport over HTTP/3 (draft-ietf-webtrans-http3-13, complete draft incl. flow control):**
  session establishment via Extended CONNECT (`:protocol=webtransport`, gated via
  SETTINGS_WT_MAX_SESSIONS + datagrams; 404 for unknown resources, H3_REQUEST_REJECTED above the
  session limit); uni streams (type 0x54) and bidi streams (WT_STREAM 0x41), both sides
  opening/receiving; WebTransport datagrams; flow control via the capsule protocol
  (WT_MAX_STREAMS/WT_MAX_DATA/WT_*_BLOCKED); session end via the WT_CLOSE_SESSION capsule (streams
  aborted with WT_SESSION_GONE); app error-code remapping (§4.3); ALPN-like protocol negotiation
  (§3.3: the client offers via `WT-Available-Protocols` — a structured-fields list of strings,
  RFC 9651 — the server picks exactly one via `WT-Protocol`; invalid value types ⇒ whole field
  ignored, a pick outside the list discarded on both sides).
  API: `ConnectWebTransport(…, availableProtocols:)`/`webTransportHandler`+`webTransportProtocolSelector`,
  `WebTransportSession` (OpenUni/Bidi, Accept*, SendDatagram, Close, `NegotiatedProtocol`).
  **Live over UDP:** `H3Get --webtransport` — session, datagram echo, uni/bidi stream (echo),
  clean shutdown, WT protocol `echo-v2` negotiated out of three offers
- **RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset):** stream reset with guaranteed partial
  delivery — the reason a receiver still sees the critical stream prefix (e.g. the WebTransport
  stream header) despite an abort. Transport parameter `reset_stream_at` (0x1d, empty value, on by
  default; non-empty ⇒ TRANSPORT_PARAMETER_ERROR) and frame RESET_STREAM_AT (0x24 =
  RESET_STREAM + reliable size; reliable > final ⇒ FRAME_ENCODING_ERROR). On the receive side the
  first reliable-size bytes are still delivered (flow control nevertheless accounts the full final
  size), later frames may only lower the reliable size (§5.2), a changed error code ⇒
  STREAM_STATE_ERROR. API: `QuicStream.ResetAt(code, reliableSize)` (guarantees bytes already sent;
  keeps retransmitting STREAM frames below it; degrades to RESET_STREAM without peer support),
  `QuicStream.PeerReliableSize`. **Live over UDP:** Cloudflare accepts TP 0x1d (handshake + 200)
- **HTTP datagrams (RFC 9297 / RFC 9221):** the foundation of MASQUE/WebTransport. QUIC layer:
  transport parameter `max_datagram_frame_size` (0x20) + `DatagramFrame` (0x30/0x31, unfragmentable,
  not retransmitted, congestion-controlled); receiving without announcement/above the limit ⇒
  PROTOCOL_VIOLATION. HTTP/3 layer: `SETTINGS_H3_DATAGRAM` (0x33) on both sides, quarter-stream-ID
  format, association with the Extended-CONNECT tunnel; unparsable/too-large ID ⇒ H3_DATAGRAM_ERROR
  (connection error), a datagram for a GET/POST ⇒ request reset (stream error). API:
  `enableDatagrams`, `Http3Tunnel.TrySendDatagram/TryReceiveDatagram`. **Live over UDP:**
  `H3Get --datagrams` — 3/3 datagrams echoed over QUIC DATAGRAM frames
- **Priorities (RFC 9218):** `priority` header (`u` 0–7, `i`; fault-tolerant structured-fields
  parsing) and PRIORITY_UPDATE frame (0xF0700, client control stream only — all §7.2 MUSTs
  enforced, updates for unopened streams buffered, update overrides the header). The QUIC send path
  schedules per §10: ascending urgency; equal urgency non-incremental in request order, incremental
  via round-robin; control/QPACK streams with urgency 0.
  API: `Http3Request.Priority`, `SendPriorityUpdate(streamId, prio)`. **Live over UDP:**
  `H3Get --priorities` — the `u=0` download overtakes the earlier-requested default download,
  and a PRIORITY_UPDATE (u=7) demotes a `u=0` prefetch afterwards
- **Malformed detection (RFC 9114 §4.1.2/§4.2/§4.3):** strict validation of pseudo-header rules
  (mandatory/forbidden/order/context, no pseudo-headers in trailers), field names (lowercase,
  token characters) and values (no NUL/CR/LF — smuggling protection), connection-specific fields
  (`te` only "trailers") and content-length consistency (exception HEAD/204/304). Malformed requests ⇒
  **400** + stream error `H3_MESSAGE_ERROR` without invoking the handler; malformed responses are
  discarded (`IsResponseMalformed`); the client throws locally on its own malformed requests.
  A valid CONNECT ⇒ **501**
- **MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2):** announcable on both sides (`maxFieldSectionSize` ⇒
  SETTINGS 0x06, formula: name + value + 32 per field). Respected on the sender side (the client
  throws on oversized request headers, the server downgrades oversized response headers to 500);
  enforced on the receiver side (server: **431** without handler invocation + STOP_SENDING
  `H3_NO_ERROR`; client: discard the response, `IsResponseTooLarge`). **Live:** Cloudflare announces
  131072 — parsed and respected
- **Trailers + interim responses (RFC 9114 §4.1):** `Http3Request.Trailers`/`Http3Response.Trailers`
  (final HEADERS frame after the content, both directions, separate from the headers) and
  `Http3Response.InterimResponses` — e.g. **103 Early Hints** as separate 1xx section(s) before the
  final response, cleanly split by `:status`. Content after an interim ⇒ malformed ⇒
  STREAM error `H3_MESSAGE_ERROR` (§4.1.2), the connection stays alive. **Live over UDP:**
  `H3Get localhost /hints` shows `103 (interim) → 200 → trailer: checksum: …`
- **GOAWAY / graceful shutdown (RFC 9114 §5.2):** `InitiateGracefulShutdown()` announces via GOAWAY
  the first request-stream ID no longer accepted; in-flight work is served to completion, later
  requests are rejected with `H3_REQUEST_REJECTED` (safely repeatable), finally `CloseGracefully()`
  with **H3_NO_ERROR**. The client refuses new requests after GOAWAY (MUST NOT) and marks in-flight
  requests ≥ the boundary as rejected; increasing GOAWAY IDs ⇒ `H3_ID_ERROR`. **Live over UDP:**
  `H3Server --goaway` + `H3Get --goaway` — GET 200 → GOAWAY → request refused → CLOSE `0x100`
- **M2 live:** `dotnet run --project samples/H3Get` fetches the real "QUIC | Cloudflare" page
  (status 200, `content-type: text/html`, `server: cloudflare`, ~126 KB body)

### QPACK (phase 6, RFC 9204 — `Http3.Qpack`)

- Encoder/decoder **without dynamic table** (spec-conformant with `QPACK_MAX_TABLE_CAPACITY=0`)
- Static table (99 entries) + Huffman (RFC 7541 App. B) + N-bit integer/string codec — the
  Huffman/static tables are generated from the RFCs by script (no hand transcription)
- Verified: RFC 9204 B.1 (decode), RFC 7541 Huffman vectors, header round-trips; the encoder
  prefers Huffman when shorter, and indexed/name-reference forms for static-table hits
- **Dynamic table (RFC 9204 §3):** `QpackDynamicTable` (FIFO with byte capacity, eviction, absolute
  indexing), `QpackDynamicEncoder` (produces insert instructions for the encoder stream + field
  section, base = required insert count) and `QpackDynamicDecoder` (Set Capacity / Insert With Name
  Reference static+dynamic / Insert With Literal Name / Duplicate; field lines indexed
  static/dynamic, **post-base**, literal names; required-insert-count modulo reconstruction §4.5.1).
  **Verified byte-exactly against RFC 9204 appendix B.2**, plus encoder↔decoder round-trip, dynamic
  reuse and eviction.
- **Wired into HTTP/3 (`Http3Qpack`):** SETTINGS announce the capacity; the peer's uni streams
  (control + QPACK encoder) are read, insert instructions processed streamingly, blocked HEADERS
  buffered and retried. **Gated:** capacity 0 = purely static (default, Cloudflare-interop-safe);
  `H3Get --qpack-dynamic` against our own server enables the dynamic table on both sides — **live
  over UDP:** a request insert (`:authority`) flows to the server, response inserts
  (`content-type`/`server`) back to the client, status 200. End-to-end test over the full stack
  (encoder-stream exchange + blocked retry).
- **Decoder-stream feedback (RFC 9204 §4.4):** after a dynamic section the decoder sends a
  **section acknowledgment**; the encoder processes section-ack/stream-cancellation/insert-count-
  increment and **releases the referenced entries**. The table never evicts a still-referenced entry
  (eviction protection, §2.1.1) — the acks keep it usable across many requests.

### Streams (phase 4, RFC 9000 §2–§4)

- `StreamId` (initiator/direction bits), `StreamReceiveBuffer` (reassembly, FIN/final size,
  flow control), `StreamSendBuffer` (frame production within the window), `QuicStream`
- Flow-control frames (`MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS`/`*_BLOCKED`),
  `RESET_STREAM`/`STOP_SENDING`; 1-RTT send path (`ShortHeader.Build`)
- `QuicClientConnection` routes incoming STREAM frames, decodes the server transport parameters
  (from EncryptedExtensions) and honours stream + connection windows when sending
- Live: Cloudflare's **HTTP/3 control stream (with SETTINGS)** and the **QPACK streams** are
  correctly reassembled and typed — direct transition to HTTP/3 (phase 7)

### Connection architecture (phase 3b)

- `TlsClientHandshake` (Quic.Tls): drives the TLS 1.3 client handshake behind the established
  "CRYPTO in / CRYPTO + keys out" interface (ClientHello, ServerHello, key schedule, Finished,
  app secrets). Verifies the server certificate (CertificateVerify signature + chain/hostname) — see
  the "Certificate validation" section.
- `QuicClientConnection` (Quic): encryption levels, `PacketNumberSpace` per space,
  CRYPTO reassembly, key installation — `Start()` / `GetDatagramsToSend()` /
  `ProcessDatagram()`. The `H3Get` sample is thereby pure UDP I/O (~60 lines).

### TLS key schedule (RFC 8446 §7.1, verified against RFC 8448)

- `KeySchedule`: early → handshake → master secret, `Derive-Secret`, handshake/application traffic
  secrets — checked byte-exactly against the RFC 8448 traces
- `Transcript` (`IncrementalHash`), `HandshakeMessages` (splitting the CRYPTO byte stream)
- `CryptoStreamAssembler` (QUIC): offset-based, cross-packet CRYPTO reassembly (receive);
  outbound, `AppendLevelPackets` distributes large CRYPTO (e.g. the PQ-hybrid ClientHello)
  offset-correctly across multiple ≤MTU Initials/Handshakes — confirmed live against Cloudflare
  with `--mlkem`

### Milestone M1 — complete handshake (sample `samples/H3Get`)

`dotnet run --project samples/H3Get` performs the **complete** QUIC/TLS 1.3 handshake against
`cloudflare-quic.com:443` — from scratch, BCL only:

1. Client Initial (ClientHello) sent, accepted and ACKed
2. **ServerHello** parsed (`AES-128-GCM-SHA256`, TLS 1.3, `key_share=secp256r1`)
3. ECDHE + transcript(CH‖SH) → handshake traffic secrets
4. **5 Handshake packets decrypted**, CRYPTO reassembled: EncryptedExtensions, Certificate,
   CertificateVerify, Finished — **server Finished MAC verified**
5. Transcript advanced → **our own (client) Finished** computed and sent in a Handshake packet,
   plus ACKs for Initial + Handshake
6. **1-RTT application keys** derived, and the server's **HANDSHAKE_DONE** received in a decrypted
   1-RTT packet → **handshake fully completed**

(The 1-RTT packets already carry Cloudflare's HTTP/3 control stream — a preview of phase 7.)

### TLS 1.3 / ClientHello (RFC 8446, RFC 9001 §8)

- `ClientHello.Build`: complete handshake message with SNI, supported_groups,
  signature_algorithms, supported_versions (TLS 1.3), key_share (P-256), ALPN (`h3`) and
  `quic_transport_parameters`; verified by structural re-parsing
- `EcdheKeyExchange`: P-256/P-384 key exchange (uncompressed point, X coordinate as the secret)
- `TransportParameters` (QUIC layer): encode/decode, ignores unknown parameters (grease)
- `TlsWriter`: length-prefixed vectors via back-patching; `BufferWriter.PatchSpan` added

### Frames (RFC 9000 §19)

- `Frame` base + `PADDING`, `PING`, `HANDSHAKE_DONE`, `CRYPTO`, `STREAM`, `ACK` (incl. ECN), `CONNECTION_CLOSE`
- `AckFrame` with an absolute range model (converts gap/length wire encoding)
- `FrameParser`: splits payloads, coalesces PADDING, reports FRAME_ENCODING_ERROR/unknown types
- Verified: the real decrypted server Initial payload (ACK + CRYPTO) from RFC 9001 A.3
  is parsed **and** re-serialised byte-exactly
- `TransportError` codes (RFC 9000 §20.1)

### Packet formats (RFC 9000 §17)

- `ConnectionId` (0–20 bytes, value equality, usable as a demux key)
- `PacketNumber`: encode/decode + length selection per RFC 9000 appendix A (tested against the examples)
- `LongHeader`: parse (cleartext fields → `PacketNumberOffset`) and build for Initial/Handshake;
  the packets built from fields match the RFC 9001 vectors byte-exactly, including a full
  send→receive round-trip (build → parse → unprotect → cleartext)
- `ShortHeader`: DCID/packet-number localisation based on the known local CID length

### Phase 1 – verified RFC 9001 vectors

- **A.1** key schedule: `initial_secret`, client/server keys, IVs, HP keys, HkdfLabel encoding
- **A.2** client Initial (1200 bytes) generated byte-exactly + header-protection mask
- **A.3** server Initial generated byte-exactly, header mask **and** decryption round-trip
- **A.4** Retry integrity tag
- **A.5** ChaCha20-Poly1305: header-protection mask `aefefe7d03` byte-exact (our own ChaCha20 block),
  plus the RFC 8439 block vector and a packet round-trip; the suite is negotiated and confirmed live
  against Cloudflare (`H3Get … --chacha20`)

Building blocks in `libs/Hermod/Hermod/QUIC/Crypto/`: `TlsHkdf`, `TrafficKeys`, `InitialSecrets`,
`PacketProtection` (AEAD **AES-GCM/ChaCha20-Poly1305** + header protection + packet-number
reconstruction), `ChaCha20` (raw block for the HP mask), `RetryIntegrity`.

## Structure

**The library itself is no longer in this repository.** QUIC moved into Hermod on 2026-07-28 and
HTTP/3 followed on 2026-07-30; what remains here are the samples, the interop evidence and the plan.

```
libs/Hermod/       The whole stack, as a submodule:
                     Hermod/QUIC/       transport (buffers, crypto, packets, frames, streams,
                                        connection, recovery, qlog) + TLS/ the TLS 1.3 handshake
                                        engine — see its README
                     Hermod/HTTP3/      HTTP/3 + QPack/ + WebSocket/ (RFC 6455) + WebTransport/
                                        (draft-13) + the async facades Http3Client/Http3Server —
                                        see its README
                     HermodTests/QUIC/  and HermodTests/HTTP3/ (247 tests, incl. RFC vectors,
                                        "evil" raw-QUIC peers and a seeded lossy link)
                   Namespaces are unchanged: org.GraphDefined.Vanaheimr.Hermod.Quic.* and
                   org.GraphDefined.Vanaheimr.Hermod.HTTP3.*
tests/             Harnesses that drive H3Server as a separate process over real UDP — see its README
                     h3semantics/       RFC 9114 semantics, driven by .NET's HttpClient over msquic
                                        (a foreign stack: no ProjectReference to Hermod)
                     h3attack/          hand-built hostile datagrams: noise, undersized Initials,
                                        version negotiation, stateless reset, amplification, flood
                     h3bench/           throughput/latency/concurrency baseline (no pass/fail)
                     h3interop/         the matrix against 8 public HTTP/3 servers — the one harness
                                        pointing outwards; live network, so nightly-only
                   run-tests.ps1 — builds, starts the demo host, runs the gated harnesses, one verdict
tools/             browser-interop.ps1 — headless Chrome/Edge against H3Server, exit code as verdict
samples/H3Get/     HTTP/3 client: GET/POST against cloudflare-quic.com or our own server
                   (--post, --cancel, --goaway, --priorities, --websocket, --datagrams, --webtransport, --zerortt, --resume, --key-update, --migrate,
                   --rotate-cid, --qpack-dynamic, --mlkem, --x448, --chacha20, --loss, --hold, -k)
samples/H3Server/  HTTP/3 server: self-signed cert, handler over UDP (routes: /, /big, POST /echo,
                   /hints with 103 + trailers; CONNECT websocket/datagram-echo, WebTransport /wt;
                   options incl. --retry/--stateless-retry, --mtls, --idle, --goaway, --ed25519/--ed448/--mldsa)
```

Namespaces: QUIC lives under `org.GraphDefined.Vanaheimr.Hermod.Quic` (+ `.Tls`, `.Core`, …) — as a
standalone transport **next to** HTTP/3, not below it; HTTP/3 under
`org.GraphDefined.Vanaheimr.Hermod.HTTP3` (+ `.Qpack`, `.WebTransport`); the tests under
`org.GraphDefined.Vanaheimr.Hermod.Tests.QUIC` / `.Tests.HTTP3`. All using blocks sit in
`#region Usings … #endregion` (Hermod style).

## Build & test

This repository builds the samples; the stack and its tests build and run in the submodule.

```bash
dotnet build
```
```bash
dotnet test libs/Hermod/HermodTests/HermodTests.csproj --filter "TestCategory!=LiveDNS"
```

Prerequisite: .NET 10 SDK.


## License

Apache License, Version 2.0 — see [LICENSE](LICENSE). The same licence the source
headers have carried all along; the file itself was simply missing.
