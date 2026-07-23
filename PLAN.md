# HTTP/3 from Scratch — Implementation Plan

**Goal:** a complete HTTP/3 stack (client + server) in C# on .NET 10, sitting directly on UDP
sockets. No external dependencies — only the BCL (`System.Net.Sockets`,
`System.Security.Cryptography`, `System.Buffers`).

**Reality check up front:** "HTTP/3 from scratch" effectively means "QUIC + TLS 1.3 from scratch".
HTTP/3 (RFC 9114) itself is the smallest layer. The lion's share of the work is:

| Layer | RFC | Share (rough) |
|---|---|---|
| QUIC transport (streams, frames, state machine) | RFC 9000 | ~35 % |
| TLS 1.3 handshake (without record layer) | RFC 8446 + RFC 9001 | ~25 % |
| Loss detection & congestion control | RFC 9002 | ~15 % |
| QPACK header compression | RFC 9204 | ~10 % |
| HTTP/3 framing & semantics | RFC 9114 | ~10 % |
| UDP I/O, buffer management, tooling | — | ~5 % |

Important: QUIC uses **no** TLS record layer. The TLS handshake messages
(ClientHello, ServerHello, …) are transported in QUIC **CRYPTO frames**; QUIC itself takes over
packet encryption using the keys derived by TLS. So we need a TLS 1.3 **handshake engine**, but
not a complete TLS stack.

---

## Available .NET building blocks (and gaps)

**Present (BCL, no "large dependency"):**
- `Socket` (UDP, `ReceiveFromAsync`/`SendToAsync`, `SocketAddress` for allocation-free I/O)
- `AesGcm` — AEAD for packet protection (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384)
- `Aes.EncryptEcb` — header protection (AES-based)
- `HKDF` (Extract/Expand) — key schedule; we write `HKDF-Expand-Label` as a thin wrapper
- `ECDiffieHellman` (P-256/P-384) — key exchange
- `SHA256`/`SHA384`, `IncrementalHash` — transcript hash
- `RSA` (PSS), `ECDsa` — verifying/creating CertificateVerify signatures
- `X509Certificate2`, `X509Chain`, `CertificateRequest` — certificates (incl. self-signed for tests)

**Gaps (checked via reflection in .NET 10):**
- **X25519 / Ed25519 / X448 / Ed448**: **not** present in the BCL. ✅ **All four** come from
  BouncyCastle (`BouncyCastle.Cryptography`) — the only external crypto dependency: X25519 + X448
  behind `IKeyExchange`, Ed25519 + Ed448 as `Ed25519Signature`/`Ed448Signature`, each encapsulated
  for the primitive only.
- **ChaCha20 (raw)**: `ChaCha20Poly1305` exists (AEAD), but header protection needs the raw
  ChaCha20 block. ✅ **Done:** our own constant-time ChaCha20 block (`Crypto/ChaCha20.cs`,
  RFC 8439 §2.3) for the HP mask; the AEAD still comes from the BCL. `TLS_CHACHA20_POLY1305_SHA256`
  is negotiated (client offer + server preference) and confirmed live against Cloudflare.
- **Present & surprisingly useful (.NET 10):** the complete PQC family `MLKem`, `MLDsa`
  (incl. `CompositeMLDsa`), `SlhDsa` — the PQ KEM part is thus BCL-native.
- **We only write the protocol logic ourselves:** QUIC, TLS 1.3 handshake, QPACK, HTTP/3 —
  **not** the crypto primitives.

---

## Project structure

```
HTTP3FromScratch.slnx
src/
  Quic.Core/             # Shared primitives – used by all layers
    VarInt.cs            # QUIC variable-length integers (RFC 9000 §16)
    Buffers/             # BufferReader/BufferWriter over Span<byte>
  Quic.Tls/              # QUIC-TLS handshake binding (RFC 8446 + 9001) – TLS 1.3 in the QUIC
                         # profile, no record layer; references only Quic.Core (no back-reference to Quic)
    Messages/            # ClientHello, ServerHello (+HRR), EE, Certificate(Verify), Finished, NST
    Crypto/              # KeySchedule, TlsHkdf, Transcript, IKeyExchange (ECDHE/X25519/X448/hybrid PQ), Ed25519/Ed448
    Handshake/           # TlsClientHandshake / TlsServerHandshake behind ITlsHandshake, certificate validation
  Quic/                  # QUIC transport (RFC 9000/9001/9002); references Quic.Tls
    Packets/             # Long/short header, PN codec, Retry, VN, stateless reset, connection ID
    Crypto/              # Initial secrets, packet/header protection (incl. ChaCha20 HP), key update
    Frames/              # All frame types + FrameParser
    Connection/          # QuicEndpoint (shared logic) + QuicClient-/QuicServerConnection, CID manager, idle
    Streams/             # QuicStream, send/receive buffer, StreamId (incl. reset/abort-read)
    Recovery/            # RTT, loss detection, PTO, NewReno, pacer (RFC 9002)
  Http3.Qpack/           # QPACK (RFC 9204): static table, Huffman (RFC 7541 App. B, generated),
                         # static + dynamic encoder/decoder
  Http3/                 # HTTP/3 (RFC 9114) + extensions + public API
    Http3ClientConnection.cs / Http3ServerConnection.cs
    Http3Client.cs / Http3Server.cs   # async API: Task facades with socket + background pump
    UdpBatchSender.cs    # UDP batching: GSO (Linux) + single-send fallback
    Http3Frame.cs / Http3Constants.cs / Http3Message.cs   # frames, error codes, request/response
    Http3Qpack.cs        # QPACK integration + uni-stream/control-stream state machine
    Http3MessageValidator.cs  # malformed detection (§4.1.2/§4.2/§4.3)
    Http3Priority.cs     # RFC 9218 (priority header/PRIORITY_UPDATE)
    Http3Tunnel.cs       # Extended-CONNECT tunnel (RFC 8441/9220)
    WebSocket/           # RFC 6455 framing (copies from Hermod.HTTP2, only the namespace swapped)
    WebTransport/        # WebTransport over HTTP/3 (draft-13): session/streams/capsules/manager
tests/
  Http3.Tests/           # 403 NUnit tests, incl. RFC test vectors and "evil" raw-QUIC peers
samples/
  H3Get/                 # HTTP/3 client CLI (GET/POST, cancel, GOAWAY, 0-RTT, … — see README)
  H3Server/              # Demo server over UDP (CID demux, Retry, stateless reset, GOAWAY, …)

Namespaces: org.GraphDefined.Vanaheimr.Hermod.Quic (+ .Tls/.Core/…) for the QUIC transport —
NEXT TO, not below HTTP/3; org.GraphDefined.Vanaheimr.Hermod.HTTP3 (+ .Qpack/.Tests) for the
HTTP/3 layer. Project/assembly names stay short. Usings in #region Usings blocks.
```

---

## Phases

**Status legend:** ✅ done · 🔶 partial · ⬜ open. Current state: 403 tests green, milestones M1–M3
reached (M1: live handshake against cloudflare-quic.com · M2: real `GET` → status 200 + 126 KB HTML ·
M3: our own HTTP/3 server, the `H3Get` client fetches status 200 over real localhost UDP).

### ✅ Phase 0 — Setup & primitives (small)
- ✅ Create solution + projects, .NET 10, `net10.0`, nullable, `AllowUnsafeBlocks` only where needed.
- ✅ **VarInt** (RFC 9000 §16): encode/decode, 1/2/4/8 bytes. Trivial, but needed everywhere.
- ✅ Span-based `BufferReader`/`BufferWriter`, `ArrayPool`-based buffer management.
- ✅ Unit-test scaffolding; test against RFC test vectors from day 1.

### ✅ Phase 1 — QUIC packet formats & Initial crypto (RFC 9000 §17, RFC 9001)
Goal: a self-built Initial packet that Wireshark decodes correctly.
- ✅ Parse/serialise long headers (Initial, Handshake, 0-RTT, Retry) and short headers (1-RTT).
- ✅ Connection IDs, packet-number encoding (truncated PN, reconstruction on receive).
- ✅ **Initial secrets**: HKDF-Extract with the fixed version-1 salt, then derive
  `client in` / `server in` (RFC 9001 §5.2).
- ✅ **Packet protection**: AEAD (AES-128-GCM **or ChaCha20-Poly1305**) with nonce = IV XOR
  packet number; the algorithm choice follows the negotiated cipher suite (`AeadAlgorithm`).
- ✅ **Header protection**: AES-ECB **or the raw ChaCha20 block** over a sample of the ciphertext,
  masks flags + PN (RFC 9001 §5.4).
- ✅ **Touchstone passed:** the complete test vectors from **RFC 9001 Appendix A** (client
  Initial, server Initial, Retry integrity tag) are reproduced byte-exactly. This is the most
  valuable single test of the whole project. **A.5 (ChaCha20 HP mask) meanwhile also byte-exact**
  (`aefefe7d03`), plus the RFC 8439 block vector and a live GET with forced ChaCha20.

### ✅ Phase 2 — TLS 1.3 handshake engine (RFC 8446, only what QUIC needs)
Goal: generate/process handshake messages and drive the key schedule.
- ✅ Messages: ClientHello, ServerHello (+ HelloRetryRequest), EncryptedExtensions, Certificate,
  CertificateVerify, Finished — build and parse. (No ChangeCipherSpec, no records — QUIC doesn't need them.)
- ✅ Extensions: `supported_versions`, `key_share` (P-256), `signature_algorithms`, `server_name`,
  `supported_groups`, **`alpn`** (= `h3`, mandatory!), **`quic_transport_parameters`** (RFC 9001 §8.2).
- ✅ Cipher suites in the ClientHello: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` offered
  (the server picks AES-128-GCM). ✅ ECDHE P-256 (`EcdheKeyExchange`), shared secret derivable.
- ✅ **Key schedule** (RFC 8446 §7.1): early → handshake → master secret; `KeySchedule` +
  `Transcript` (`IncrementalHash`); `HKDF-Expand-Label`. Handshake traffic secrets derived,
  server Handshake packets from cloudflare-quic.com **decrypted live**.
- ✅ Reading handshake messages: `HandshakeMessages` splits the (reassembled) CRYPTO stream
  into EncryptedExtensions/Certificate/CertificateVerify/Finished.
- ✅ CertificateVerify: signature over the transcript verified (ECDSA P-256/P-384, RSA-PSS) with the
  leaf key — **always**, as the cryptographic binding to the handshake; chain validation via
  `X509Chain` + hostname (`X509Certificate2.MatchesHostname`) per `CertificateValidationOptions`
  (`Default` = full validation against system roots; `Insecure` = like `curl -k`; `CustomTrustRoots`
  for test certificates). Confirmed live against Cloudflare with full chain validation
  (`CN=cloudflare-quic.com`).
- ✅ Finished MAC (HMAC over the transcript): server Finished verified **and** our own (client)
  Finished computed and sent live (`KeySchedule.FinishedVerifyData`, `Finished.BuildMessage`).
- ✅ Client application (1-RTT) secrets derived (`DeriveApplicationSecrets`); the server's 1-RTT
  packets (incl. HANDSHAKE_DONE) decrypted live.
- ✅ Client and server side as an explicit state machine (`TlsClientHandshake`/`TlsServerHandshake`
  behind `ITlsHandshake`); interface to the QUIC layer: "CRYPTO bytes in at level X" / "CRYPTO bytes
  out for level Y" / "new keys available for level Z" (analogous to the ngtcp2/quiche model).
- ✅ **Touchstone passed:** key-schedule test vectors from **RFC 8448** (TLS 1.3 traces) are
  recomputed byte-exactly (early/handshake secret, c/s hs traffic, traffic-key derivation).

### ✅ Phase 3 — QUIC connection establishment (RFC 9000 §5–§7, §12–§14)
Goal: complete handshake against a real server (e.g. `cloudflare-quic.com`).
- ✅ First-hour frames: `PADDING`, `PING`, `ACK`, `CRYPTO`, `CONNECTION_CLOSE` (+ STREAM,
  HANDSHAKE_DONE). Parsing/serialising verified against the RFC 9001 A.3 payload.
- ✅ Encryption levels: Initial, Handshake, 1-RTT (+ 0-RTT) — keys + packets of all levels.
  ✅ Coalesced packets (multiple QUIC packets per UDP datagram) are parsed.
- ✅ Connection state machine: reusable `QuicClientConnection` with encryption levels,
  packet-number spaces (`PacketNumberSpace`), CRYPTO reassembly and the TLS engine
  (`TlsClientHandshake`, "CRYPTO in / CRYPTO + keys out" model) — drives the handshake up to
  HANDSHAKE_DONE; explicit closing/draining/closed state, idle timeout and server side
  (see phase 8 / M3).
- ✅ ACK generation: ranges from received packet numbers (`AckFrame.FromPacketNumbers`), permanent;
  ack_delay and ACK processing/loss detection implemented in phase 5.
- ✅ Transport parameters: encode/decode (`TransportParameters`) and application of the negotiated
  limits (flow control, stream limits, idle timeout, active_connection_id_limit, …).
- ✅ **CRYPTO data across packets**: receive (`CryptoStreamAssembler`, offset-based,
  unordered/overlapping — Cloudflare's certificate chain reassembled across 5 Handshake packets)
  **and send** (`AppendLevelPackets` distributes outgoing CRYPTO offset-correctly across multiple
  Initial/Handshake packets, each ≤ MTU, `MaxCryptoDataPerPacket = 1000`). The PQ-hybrid ClientHello
  (X25519MLKEM768, ~1450 bytes) thus goes out as **two** ≤1252-byte Initials (instead of one
  oversized datagram); regression test over the datagram path + confirmed live against Cloudflare
  (normal **and** `--mlkem`, status 200 each).
- ✅ UDP loop: sending/receiving (samples `H3Get`/`H3Server`) incl. **demultiplexing by destination
  connection ID** (migration-capable, see phase 8); single-writer/channel architecture → phase 9.
- ✅ Pad the client Initial to ≥ 1200 bytes (`InitialPacketFactory`); ✅ anti-amplification limit
  (3×) server-side (see phase 8, tested in-process).
- ✅ **Milestone M1 reached:** **complete** handshake with cloudflare-quic.com — ClientHello
  → ServerHello → server flight decrypted & Finished verified → own Finished + ACKs
  sent → **HANDSHAKE_DONE** received in a 1-RTT packet. Handshake completed, 1-RTT keys
  active. ✅ Clean `CONNECTION_CLOSE`/draining and idle timeout since implemented (phase 8).
- ✅ ACK generation from received packet numbers (`AckFrame.FromPacketNumbers`); parsing NEW_TOKEN /
  NEW_CONNECTION_ID / RETIRE_CONNECTION_ID (1-RTT flight).

### ✅ Phase 4 — Streams & flow control (RFC 9000 §2–§4, §19)
- ✅ `STREAM` frames (offset/FIN/length variants), reassembly of out-of-order data
  (`StreamReceiveBuffer` with final-size/flow-control checking; `StreamSendBuffer`).
- ✅ Bidirectional + unidirectional streams, stream-ID assignment (`StreamId`, bit encoding).
  Server streams (HTTP/3 control + QPACK) from cloudflare-quic.com reassembled live.
- ✅ Flow control: frames `MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS`/`DATA_BLOCKED`/
  `STREAM_DATA_BLOCKED`/`STREAMS_BLOCKED`; send-window observance (stream + connection),
  peer limits decoded from EncryptedExtensions; receive-side MAX_* replenishing
  (`CollectFlowControlFrames`: replenished once half the window is consumed);
  dynamic window auto-tuning → phase 9.
- ✅ `RESET_STREAM` / `STOP_SENDING` **complete** (send/receive/retransmission,
  §3.5 solicited reset, final-size/state validation — details in phase 8).
- ✅ Stream API: `QuicStream` (`Write`/`Finish`/`Read`/`Reset`/`AbortRead`);
  async/backpressure API → phase 9.
- ✅ 1-RTT send path (`ShortHeader.Build`) — app packets with ACK + STREAM frames.

### ✅ Phase 5 — Loss detection & congestion control (RFC 9002)
Without this phase everything only works in the lab; with packet loss the handshake would otherwise break.
- ✅ RTT estimation (`RttEstimator`: smoothed_rtt, rttvar, min_rtt; ack_delay considered).
- ✅ Loss detection (`LossRecovery`): packet threshold (3) + time threshold; probe timeout (PTO)
  with backoff.
- ✅ Retransmission: lost **frames** (CRYPTO/STREAM) are re-queued and repacked.
- ✅ Congestion control: **NewReno** (`NewRenoCongestionControl`: slow start, congestion avoidance,
  recovery).
- ✅ **cwnd enforcement + pacing in the send path** (RFC 9002 §7/§7.7): new stream data is limited
  per `GetDatagramsToSend` by `min(cwnd − bytes_in_flight, pacing budget)`; the `Pacer`
  (token bucket, rate `1.25·cwnd/smoothed_rtt`, burst cap ≈ initial window) spreads it over time.
  Pure ACKs and PTO probes are exempt. The 1-RTT send path now emits multiple **MTU-sized**
  packets per call instead of one oversized one.
- ✅ **Persistent congestion** (RFC 9002 §7.6): collapses the window to `kMinimumWindow` when two
  ack-eliciting packets are lost, nothing was acknowledged in between and their send spacing exceeds
  the PC duration `(srtt + max(4·rttvar, granularity) + max_ack_delay)·3` (only after the first
  RTT sample). Conservative approximation via consecutive packet numbers (no false positives).
- ✅ **Idle timeout** (RFC 9000 §10.1): `IdleTimeout` negotiates `min(local, peer)` (0 = disabled),
  raises to at least `3·PTO`, restarts the timer on successful receive and on sending an
  ack-eliciting packet (only once per receive). `QuicEndpoint.CheckIdleTimeout()` closes the
  connection silently (no more datagrams). H3Server reaps inactive connections (`--idle=<ms>`).
- ✅ **Keep-alive via PING** (RFC 9000 §10.1.2): `KeepAliveInterval` set ⇒ after that much inactivity
  a PING (ack-eliciting) is scheduled, resetting the idle timeout on both sides.
  `IdleTimeout.ShouldSendKeepAlive` controls the cadence; shown live with `H3Get --hold=<s>` against
  a server with a short `--idle` (connection survives where it would otherwise be reaped).
- ✅ **Touchstone passed:** sample `H3Get --loss=N` drops a fraction of the datagrams;
  handshake + 126 KB GET survive 10 % loss (≈17 datagrams dropped, bridged via retransmission).
  RTT/NewReno/LossRecovery/**Pacer**/**persistent congestion** secured by unit tests;
  a 150 KB in-process transfer proves that the paced, cwnd-limited send path transmits
  byte-exactly and MTU-conformantly.

### ✅ Phase 6 — QPACK (RFC 9204), minimal but correct
- ✅ **Stage 1 (sufficient for full interop):** encoder/decoder without dynamic table —
  static table (99 entries, `QpackStaticTable`) + literals, Huffman (`Huffman`, table from
  RFC 7541 App. B, generated by script), N-bit integer and string codec (`QpackPrimitives`).
  Verified: RFC 9204 B.1 example (decode), RFC 7541 Huffman vectors, round-trips of typical
  request headers. `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` is announced → the peer stays static
  too; references to the dynamic table are rejected (`QpackResult.DynamicTableReference`).
- ✅ Encoder/decoder streams (mandatory in HTTP/3): opened and wired on both sides (stage 2 below +
  phase 7); with capacity 0 they stay practically empty.
- ✅ **Stage 2 (dynamic table):** `QpackDynamicTable` (FIFO, byte capacity, eviction, absolute
  indexing), `QpackDynamicEncoder` (produces insert instructions + field section, base = RIC →
  pre-base), `QpackDynamicDecoder` (encoder stream: Set Capacity / Insert Name-Ref static+dynamic /
  Insert Literal / Duplicate; field section: indexed static/dynamic, post-base, literal names;
  RIC modulo reconstruction §4.5.1). **Verified byte-exactly against RFC 9204 appendix B.2**
  (decode), plus round-trip/reuse/eviction. **Wired into the live HTTP/3 path** (`Http3Qpack`):
  SETTINGS announce the capacity, the peer's uni streams (control + QPACK encoder) are read,
  instructions processed streamingly, blocked HEADERS buffered and retried (blocked-streams
  handling). Gated: capacity 0 = purely static (Cloudflare stays that way); `--qpack-dynamic`
  enables it against our own server. **Confirmed live over UDP** (request/response inserts flow
  in both directions, status 200).
- ✅ **Decoder-stream feedback** (RFC 9204 §4.4): after a dynamic section the decoder sends a
  **section acknowledgment** (on the QPACK decoder stream); the encoder processes section-ack /
  stream-cancellation / insert-count-increment and thereupon releases the **references**. The table
  counts references and never evicts a still-referenced entry (eviction protection, §2.1.1) —
  without acks, references pile up and inserts fall back to literals; with acks the table stays
  usable. Tested in-process (ack releases the reference → eviction possible again) and live
  (the server receives the client's acks).

### ✅ Phase 7 — HTTP/3 (RFC 9114) — feature audit complete
Deliberately left open: server push (MAY), classic CONNECT proxying.
- ✅ **WebTransport over HTTP/3** (draft-ietf-webtrans-http3-13) — the complete draft incl. flow control:
  - **Session establishment** (§3): Extended CONNECT with `:protocol = webtransport`; gating via
    SETTINGS_WT_MAX_SESSIONS (0x14e9cd29) + ENABLE_CONNECT_PROTOCOL + H3/QUIC datagrams (§3.1);
    without datagrams ⇒ malformed; unknown resource ⇒ 404; above WT_MAX_SESSIONS ⇒
    H3_REQUEST_REJECTED (§5.2). `Http3ClientConnection.ConnectWebTransport`/
    `TryGetWebTransportSession`, server `webTransportHandler`.
  - **Streams** (§4.1/§4.2): unidirectional (type 0x54 ‖ session ID), bidirectional (WT_STREAM 0x41 ‖
    session ID); both sides open/receive; routing via `WebTransportManager` (client- and
    server-initiated), early-arriving streams buffered (§4.5, overflow ⇒ WT_BUFFERED_STREAM_REJECTED).
    Reset/StopSending map 32-bit app codes byte-exactly into the WT_APPLICATION_ERROR range (§4.3);
    direction-dependent (send-only uni ⇒ only RESET, receive-only uni ⇒ only STOP_SENDING).
  - **Datagrams** (§4.4): via the HTTP-datagram infrastructure (quarter stream ID = CONNECT stream).
  - **Flow control** (§5): capsule protocol (RFC 9297 §3.2) on the CONNECT stream; WT_MAX_STREAMS
    (0x190B4D3F/40), WT_MAX_DATA (0x190B4D3D), WT_STREAMS_BLOCKED/WT_DATA_BLOCKED — limits from
    SETTINGS_WT_INITIAL_MAX_* + proactive replenishing; active only with WT_MAX_SESSIONS > 1 (§5.1).
  - **Session end** (§6): WT_CLOSE_SESSION capsule (0x2843, 32-bit code + UTF-8 reason) + FIN; clean
    FIN = code 0; all associated streams aborted with WT_SESSION_GONE.
  - **Protocol negotiation** (§3.3, ALPN-like): the client offers via `WT-Available-Protocols`
    (structured-fields list of strings, RFC 9651, preference first); the server picks EXACTLY one of
    them via `WT-Protocol` (SF item string) in the 2xx response. Non-string values invalidate the
    ENTIRE field, parameters are ignored, a pick outside the offer list is discarded on both sides
    (all §3.3 MUSTs). API: `ConnectWebTransport(…, availableProtocols:)`, server ctor
    `webTransportProtocolSelector`, `WebTransportSession.NegotiatedProtocol`;
    SF encoding in `WebTransportProtocols` (own strict RFC 9651 parser for list/item/string
    incl. skipping parameters of all bare-item types).
  - **Keying-material exporter** (§4.7): TLS exporter (RFC 8446 §7.5) over the newly derived
    `exporter_master_secret` (§7.1, verified against RFC 8448) — chain KeySchedule →
    ITlsHandshake/both handshakes → `QuicEndpoint.ExportKeyingMaterial` →
    `WebTransportSession.ExportKeyingMaterial` (label fixed `EXPORTER-WebTransport`, context =
    session ID(64) ‖ app label(1–255) ‖ app context(0–255) ⇒ separate material per session,
    identical per session end).
  - 7 tests (error mapping, capsule reader, support gating, session/404, datagram+uni+bidi echo
    end-to-end, close with code/reason, session limit) + 7 tests protocol negotiation (SF
    encoding/rejection, end-to-end pick, out-of-list guard, without offer) + 5 tests exporter
    (RFC 8448 vector, determinism/label-context separation, QUIC end-to-end, before handshake,
    WT sessions). **Live over UDP:** `H3Get --webtransport` against `H3Server` — session, datagram
    echo, uni/bidi stream (echo), clean shutdown, WT protocol `echo-v2` negotiated out of
    `echo-v3, echo-v2, echo-v1`, keying-material export byte-identical in both processes; all other
    sample modes + Cloudflare regression-free. **With this, draft-webtrans-http3-13 is COMPLETE.**
- ✅ **RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-08)** — stream reset with guaranteed
  partial delivery (the foundation for the WebTransport stream prefix arriving despite a reset):
  - **Transport parameter** `reset_stream_at` (0x1d, empty value): announces receive readiness
    (on by default); non-empty value ⇒ TRANSPORT_PARAMETER_ERROR. `PeerSupportsResetStreamAt`
    controls whether we may send AT frames to the peer.
  - **Frame** RESET_STREAM_AT (type 0x24): like RESET_STREAM plus reliable size. Reliable size >
    final size ⇒ FRAME_ENCODING_ERROR.
  - **Receive side:** delivers the first reliable-size bytes onward to the application (read offset
    decoupled from the flow-control accounting, which books the full final size); later frames may
    only lower the reliable size (§5.2, increases from reordering are ignored), a changed error
    code ⇒ STREAM_STATE_ERROR.
  - **Send side:** `QuicStream.ResetAt(code, reliableSize)` guarantees bytes already sent
    (reliable size clamped to the send offset); STREAM frames below the reliable size keep being
    retransmitted on loss; without peer support the abort degrades to RESET_STREAM.
  - 13 tests (frame round-trip/truncation, TP encoding/rejection, receive partial delivery/lowering/
    error-code change/late-frame trimming, send emission/degradation/clamping, end-to-end over real
    QUIC frames). **Live over UDP:** Cloudflare accepts TP 0x1d (handshake + GET 200).
- ✅ **HTTP datagrams (RFC 9297) over QUIC DATAGRAM (RFC 9221)** — the foundation of MASQUE/WebTransport:
  - **QUIC layer (RFC 9221):** transport parameter `max_datagram_frame_size` (0x20, send/parse),
    `DatagramFrame` (type 0x30 without / 0x31 with length), emission in the 1-RTT send path
    (unfragmentable ⇒ one frame per packet, congestion-controlled, NOT retransmitted), receive with
    PROTOCOL_VIOLATION on missing announcement or oversize (§3). API: `TrySendDatagram`
    (refuses without peer TP / above MTU) + `TakeReceivedDatagrams`.
  - **HTTP/3 layer (RFC 9297):** setting `SETTINGS_H3_DATAGRAM` (0x33, value 0/1 otherwise
    H3_SETTINGS_ERROR), bilateral negotiation (`DatagramsNegotiated` = setting sent+received AND
    max_datagram_frame_size > 0). HTTP/3 datagram format = quarter stream ID (stream ID / 4) +
    payload; association with the request stream/tunnel. Errors: unparsable/too-large quarter
    stream ID ⇒ H3_DATAGRAM_ERROR (0x33, connection error); datagram for a request without
    datagram semantics (e.g. GET) ⇒ abort the request with H3_DATAGRAM_ERROR (stream error);
    unknown stream ⇒ drop silently. `Http3Tunnel.TrySendDatagram/TryReceiveDatagram` (unreliable:
    overflow drops the oldest).
  - 7 tests (frame round-trip both variants, no negotiation ⇒ no sending, **echo end-to-end over
    the tunnel**, GET+datagram ⇒ stream reset, malformed ⇒ connection error, unknown stream
    dropped, invalid setting value). **Live over UDP:** `H3Get --datagrams` against `H3Server`
    (route `datagram-echo`) — negotiation, CONNECT 200, 3/3 datagrams echoed in DATAGRAM frames;
    Cloudflare GET regression-free.
- ✅ **WebSockets over HTTP/3 (RFC 9220 / RFC 8441 / RFC 6455)**:
  - **RFC 6455 framing reused:** the WebSocket files from Hermod (`Hermod.HTTP2.WebSocket*`
    + `IHTTP2Tunnel`) are adopted under `src/Http3/WebSocket/` as **byte-identical copies** (only
    change: namespace line → `…Hermod.HTTP3`) — the framing is written transport-agnostically
    against the 2-method tunnel interface; dedup plan in the README there.
  - **Extended CONNECT (RFC 8441)**: SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08, value MUST be 0/1
    otherwise H3_SETTINGS_ERROR); `:protocol` pseudo-header in the validator (only on CONNECT; with
    :protocol, :scheme/:path MUST be present, :authority per normal rules; classic CONNECT
    unchanged). Client `SendExtendedConnect` (throws without the server setting, §3 MUST NOT) +
    `TryGetConnectResponse`; server `connectHandler` (announces the setting; unknown :protocol ⇒
    **501**, RFC 9220 §3; Extended CONNECT without the setting ⇒ malformed/400).
  - **Tunnel mode** (`Http3Tunnel : IHTTP2Tunnel`): CONNECT is handled IMMEDIATELY at the HEADERS
    (no FIN waiting); after 2xx the tunnel bytes travel in DATA frames (RFC 9114 §4.4 — other
    known frames ⇒ H3_FRAME_UNEXPECTED); FIN ≙ orderly TCP close, reset ≙ RST with
    H3_REQUEST_CANCELLED (RFC 9220 §3). Async bridge single-threaded: pending `ReadAsync` are
    completed inline in the pump (race-free without locks).
  - 7 tests (setting gate both sides, 501, **text/binary echo + close handshake end-to-end**,
    permessage-deflate negotiated + round-trip, DATA-only MUST, :protocol validator).
    **Live over UDP:** `H3Get --websocket` — setting → CONNECT 200 → RFC 6455 text echo →
    close handshake → orderly tunnel end; Cloudflare GET regression-free.
- ✅ **Priorities (RFC 9218)** — the only "important" extension, now implemented:
  - **Signals**: `priority` header (structured-fields dictionary, parsed fault-tolerantly:
    unknown/wrong-typed/out-of-range parameters are ignored — MUST; `u` 0–7 default 3,
    `i` boolean default false; `Http3Priority.Parse/ToHeaderValue`) and the **PRIORITY_UPDATE**
    frame (0xF0700, payload = element-ID varint + ASCII field value) — `Http3Request.Priority` and
    `Http3ClientConnection.SendPriorityUpdate(streamId, priority)`.
  - **MUSTs (§7.2)**: PRIORITY_UPDATE only on the client control stream (otherwise
    H3_FRAME_UNEXPECTED, also for the client as receiver — servers NEVER send); non-request stream
    ID ⇒ H3_ID_ERROR; push variant 0xF0701 ⇒ H3_ID_ERROR (never promised); layout ⇒ H3_FRAME_ERROR.
    Updates for not-yet-opened streams are buffered (last wins, capped at 32) and applied on open;
    an update **overrides** the header (§7).
  - **Server scheduling (§10)**: `QuicStream.SendUrgency/SendIncremental` + prioritised stream
    selection in the QUIC send path (`PickSendStream`): ascending urgency; equal urgency
    non-incremental ⇒ exclusively in ascending stream ID (request order), incremental ⇒ round-robin
    (share bandwidth). Control/QPACK streams run with urgency 0 (never starve).
  - 10 tests (parser, urgency ordering, FIFO, incremental sharing, header override, buffering before
    stream open, 4 state-machine MUSTs). **Live over UDP**: `H3Get --priorities` against
    `H3Server` (route `/big`) — the u=0 download overtakes the earlier-requested default download,
    and a PRIORITY_UPDATE (u=7) demotes a u=0 "prefetch" behind u=3 afterwards.
    Cloudflare GET regression-free.
- ✅ Unidirectional streams with type prefix: control (0x00), QPACK encoder (0x02) /
  decoder (0x03); control stream opened, `SETTINGS` as the first frame.
- ✅ Frames: `DATA`, `HEADERS`, `SETTINGS` (incremental parsing, unknown frames ignored –
  greasing). `MAX_PUSH_ID`/`CANCEL_PUSH` deliberately validating only (no push).
- ✅ **MAX_FIELD_SECTION_SIZE** (RFC 9114 §4.2.2): size formula Σ(name + value + 32) per field,
  uncompressed (`Http3Qpack.FieldSectionSize`). Both sides can announce a limit
  (`maxFieldSectionSize` parameter ⇒ SETTINGS 0x06) and parse the peer's. **Sender (SHOULD NOT):**
  the client throws on oversized request headers/trailers (`ArgumentException`); the server
  downgrades oversized response headers to a minimal **500**, omits oversized interim/trailer
  sections. **Receiver (MAY):** the server answers oversized request headers with **431**
  (RFC 6585) without handler invocation + STOP_SENDING H3_NO_ERROR (§4.1); the client discards
  oversized responses (`IsResponseTooLarge`, stream abort, connection lives). 5 tests (formula,
  client refusal, 431 via raw client, 500 downgrade, client discard via raw server). **Live:**
  Cloudflare announces **131072** (parsed, respected); our own H3Server announces 16384 — GET
  status 200 each.
- ✅ **Trailer sections + interim responses (1xx)** (RFC 9114 §4.1): `Http3Request.Trailers`/
  `Http3Response.Trailers` are sent as a final HEADERS frame after the content and stored separately
  from the header section on receive (both directions). `Http3Response.InterimResponses`
  (e.g. **103 Early Hints**): the server sends one 1xx HEADERS section per interim BEFORE the
  final response; the client splits them cleanly by `:status` (100–199) — the final header section
  stays pure. Violation "content after interim" (interims carry no content) ⇒ **malformed** ⇒
  STREAM error `H3_MESSAGE_ERROR` (§4.1.2, `IsResponseMalformed`; connection lives on). 5 tests
  (trailers both sides, trailers without content, 2× 103 + final response, malformed via raw
  server). **Live over UDP:** `H3Get localhost /hints` — "HTTP/3 103 (interim) — link: …preload…" →
  200 → "trailer: checksum: …"; Cloudflare GET regression-free.
- ✅ **GOAWAY / graceful shutdown** (RFC 9114 §5.2): server `InitiateGracefulShutdown()` sends GOAWAY
  with the first request-stream ID NO LONGER accepted (`GoAwaySent`), serves in-flight work to
  completion (`HasPendingRequests`), rejects later request streams with RESET_STREAM/STOP_SENDING
  `H3_REQUEST_REJECTED` (no handler invocation, no connection error) and afterwards closes via
  `CloseGracefully()` with **H3_NO_ERROR** (type 0x1d). Client: `GoAwayStreamId`, `SendRequest`
  throws after GOAWAY (MUST NOT), in-flight requests ≥ the boundary are marked `IsRequestRejected`
  (safely repeatable) and cleaned up on the transport side; increasing GOAWAY IDs ⇒ H3_ID_ERROR.
  4 tests (end-to-end, late request via raw client, in-flight rejection, ID increase);
  **live over UDP:** `H3Server --goaway` + `H3Get --goaway` — GET 200 → GOAWAY (boundary 4) → new
  request correctly refused → CONNECTION_CLOSE 0x100 (H3_NO_ERROR).
- ✅ Request/response: pseudo-headers (`:method`/`:scheme`/`:authority`/`:path`/`:status`),
  mapping request ↔ bidirectional stream.
- ✅ **Malformed detection** (RFC 9114 §4.1.2/§4.2/§4.3, `Http3MessageValidator` — deliberately
  strict): pseudo-header obligations (exactly one `:method`/`:scheme`/`:path`; `:authority` OR
  `Host`, non-empty, consistent, without userinfo; exactly one numeric `:status` 100–599),
  undefined/out-of-context pseudo-headers, pseudo-headers after regular fields or in trailers,
  uppercase/invalid characters in field names, NUL/CR/LF in values (smuggling protection),
  connection-specific fields (`connection`/`keep-alive`/`transfer-encoding`/`upgrade`/…; `te` only
  "trailers") and content-length consistency (= Σ DATA lengths; exception body-less responses:
  HEAD/204/304). **Reaction:** server ⇒ **400** (MAY) + read abort with stream error
  `H3_MESSAGE_ERROR`, no handler invocation; client ⇒ discard the response (MUST NOT accept,
  `IsResponseMalformed`); the client throws locally on its own malformed requests (`SendRequest`,
  `ArgumentException`, MUST NOT generate). A valid **CONNECT** (§4.4) is recognised and answered
  with **501** (not supported). 15 tests (validator units + wire level with raw peers; uppercase
  reproduced via literal-literal QPACK since our encoders lowercase names by convention). **Live:**
  Cloudflare GET (their `content-length` genuinely passes the consistency check), locally `/hints`
  + POST echo — status 200 each.
- ✅ **Request bodies** (RFC 9114 §4.1): `Http3Request.Body`/`Post(...)` — the client sends the body
  as a DATA frame after the HEADERS frame (with automatic `content-length`, §4.1.2: value = sum of
  the DATA lengths); the server collects DATA frames and only answers once the message is complete
  (FIN). A trailer section (second HEADERS) is decoded QPACK-correctly (section acks), its content
  still discarded. Tests: POST echo (headers + body byte-exact) and **120 KB upload** — drives the
  client send path (cwnd/pacing/MTU) under load for the first time, SHA-256-verified. **Live:**
  POST `/echo` against our own H3Server over UDP (echo byte-exact) and POST against
  cloudflare-quic.com (status 200) — `H3Get --post=<text>`.
- ✅ Error handling: H3 error codes (RFC 9114 §8.1) as `Http3Error` constants; **request
  cancellation** (§4.1.1): `CancelRequest` resets the send side and aborts reading (both
  H3_REQUEST_CANCELLED); the server detects client aborts (RESET_STREAM ⇒ reset its own response
  side H3_REQUEST_REJECTED/CANCELLED, STOP_SENDING ⇒ automatic reset via RFC 9000 §3.5);
  `IsRequestCancelled`/`RequestResetErrorCode`; an already-complete response stays usable.
  **Live:** `H3Get --cancel` against cloudflare-quic.com — abort mid-download, Cloudflare
  resets with 0x10c (copied code), second GET over the same connection status 200.
- ✅ **Frame/stream state machine** (§4.1, §6.2, §7.2) — violations ⇒ CONNECTION_CLOSE **type 0x1d**
  (`CloseApplication` in the QUIC layer) with H3 error code:
  - Control stream: first frame MUST be SETTINGS (H3_MISSING_SETTINGS), second SETTINGS/DATA/
    HEADERS/PUSH_PROMISE ⇒ H3_FRAME_UNEXPECTED; second control/QPACK stream ⇒
    H3_STREAM_CREATION_ERROR; closing/resetting critical streams ⇒ H3_CLOSED_CRITICAL_STREAM
    (§6.2.1, RFC 9204 §4.2).
  - Request streams: DATA before HEADERS / frames after the trailer section, SETTINGS/GOAWAY/
    MAX_PUSH_ID/CANCEL_PUSH ⇒ H3_FRAME_UNEXPECTED; PUSH_PROMISE: from the client ⇒
    H3_FRAME_UNEXPECTED (server), without MAX_PUSH_ID ⇒ H3_ID_ERROR (client); push stream:
    client-initiated ⇒ H3_STREAM_CREATION_ERROR, without MAX_PUSH_ID ⇒ H3_ID_ERROR.
  - Reserved HTTP/2 frame types (0x02/0x06/0x08/0x09) ⇒ H3_FRAME_UNEXPECTED (§7.2.8); reserved/
    duplicate SETTINGS IDs ⇒ H3_SETTINGS_ERROR; layout errors (GOAWAY/CANCEL_PUSH/MAX_PUSH_ID ≠
    exactly one varint, SETTINGS leftovers, truncated final frame at FIN) ⇒ H3_FRAME_ERROR (§7.1).
  - GOAWAY with a non-request stream ID at the client ⇒ H3_ID_ERROR (§7.2.6; `GoAwayId` recorded —
    semantics followed with the GOAWAY step). Grease frames/settings (0x1f·N+0x21) are ignored; our
    own SETTINGS now contain a grease setting (§7.2.4.1 SHOULD). 14 tests with an "evil" raw-QUIC
    peer in both directions; **live:** GET + 0-RTT against Cloudflare and our own server (dyn.
    QPACK) run unchanged — the stricter validation breaks no interop.
- ✅ Public API: `Http3ClientConnection` (`InitializeHttp3`/`SendRequest`/`TryGetResponse`/
  `CancelRequest`, transport-agnostic) **and** `Http3ServerConnection` (handler model,
  `InitiateGracefulShutdown`); ergonomic `Http3Client.GetAsync(uri)` wrapper → phase 9.
- ✅ Server push omitted (MAY; PUSH-related frames/streams are rejected with validation).
- ✅ **Milestone M2 reached:** `GET https://cloudflare-quic.com/` delivers status 200 + 126 KB
  HTML over our own stack (QPACK-decoded headers, body reassembled).
- ✅ **Client interop matrix — 8 independent QUIC implementations** (all live over UDP, with
  **full** certificate chain + hostname validation, without `-k`; as of 2026-07-23):

  | Target | Foreign stack | KEX / suite / cert | Result |
  |---|---|---|---|
  | cloudflare-quic.com / cloudflare.com | **quiche** (Cloudflare) | X25519 / AES-128-SHA256 / ECDSA | 200 / 301 |
  | quic.nginx.org | **nginx QUIC** | X25519 / AES-128-SHA256 / ECDSA P-256 | 200 |
  | www.google.com | **Google QUIC** | X25519 / AES-128-SHA256 | 200 |
  | www.facebook.com | **mvfst** (Meta) | X25519 / AES-128-SHA256 | 302 |
  | www.litespeedtech.com | **lsquic** (LiteSpeed) | X25519 / AES-128-SHA256 | 200 |
  | outlook.office.com | **msquic** (Microsoft) | **P-256 / AES-256-SHA384 / RSA** | 301 |
  | caddyserver.com / http3.is | **quic-go** (Go, via Caddy) | X25519 / AES-128 & AES-256 / ECDSA & RSA | 200 |
  | www.akamai.com | **Akamai QUIC** | X25519 / **AES-256-SHA384** / ECDSA | 403* |

  *403/301/302 are regular HTTP responses (bot protection/redirect) — the HTTP/3 stack runs
  end-to-end in all cases. The matrix covers both KEX groups (X25519 **and** P-256), both suites
  (AES-128-GCM-SHA256 **and** AES-256-GCM-SHA384) and both certificate types (ECDSA **and**
  RSA-PSS) — outlook.office.com is the only one exercising the complete P-256 + AES-256 + RSA path
  live. (Note: `www.microsoft.com` offers no HTTP/3 at all — cross-checked with
  `curl --http3-only`.) **Repeatable at any time** via
  `dotnet run --project samples/H3Get -- --interop`; maintained in
  [INTEROP.md](INTEROP.md) (which also holds the server-side `curl` evidence).
- ✅ **Milestone M3 reached (via our own client):** server side built — `TlsServerHandshake`
  (ServerHello/EE/Certificate/CertificateVerify signature/Finished, client-Finished verification),
  `ServerCertificate` (self-signed ECDSA P-256 via `CertificateRequest`), `QuicServerConnection`,
  `Http3ServerConnection`. Sample `H3Server` (UDP): our `H3Get` client fetches status 200 + HTML
  over real localhost UDP; additionally an in-process test (client↔server, both from scratch).
  ✅ Interop building blocks: **X25519** (BouncyCastle, `IKeyExchange`) and **HelloRetryRequest**
  (client + server) implemented. The client offers X25519+P-256; the server picks from the key
  shares or sends an HRR. Live proof: X25519 is negotiated against cloudflare-quic.com.
- ✅ **`curl --http3` interop (server side)** — against TWO independent foreign HTTP/3 stacks:
  - **Windows:** official curl 8.21.0 package (curl.se, **ngtcp2 1.24 + nghttp3 1.17 + LibreSSL
    4.3.2**) → `curl --http3-only -k https://127.0.0.1:4433/` against `H3Server`: handshake, GET 200
    (HTML), POST /echo (body echoed byte-exactly), GET /big (300 000 B in ~22 ms), GET /hints
    (**103 Early Hints + final 200 + trailer `checksum` displayed by curl**), connection reuse.
  - **WSL (Debian 13):** distro curl 8.14.1 with **OpenSSL-3.5-QUIC** (curl's openssl-quic backend,
    no ngtcp2!) + nghttp3 → the same tests across the WSL2 NAT boundary (host IP from `ip route`):
    GET 200, POST echo, 300 000 B in ~38 ms, 103+trailers; clean closes (error code 0).
  - With this, the server side is interop-confirmed against ngtcp2/LibreSSL, OpenSSL-QUIC AND
    (client side) Cloudflare's quiche. (The local system curl is a Schannel build without HTTP/3 —
    the HTTP/3-capable curl sits as an unpacked package in the session scratchpad; in WSL it is
    preinstalled.)

### 🔶 Phase 8 — Robustness & server completeness
- ✅ **Version negotiation** (RFC 9000 §6): the server sends a VN packet on an unsupported version
  (`VersionNegotiationPacket`, DCID/SCID swapped, supported versions listed). **Anti-amplification
  (§6.1/§14.1):** no VN for datagrams < 1200 B. **GREASE (§6.3):** a reserved version matching
  `0x?a?a?a?a` is included (probes client robustness, prevents ossification). The client detects VN
  (version field 0), discards it per the §6.2 rules (already processed a packet / own version
  listed), ignores the reserved version and otherwise gives up
  (`VersionNegotiationReceived`/`OfferedVersions`). Tested in-process (receive, GREASE version,
  no VN for a too-small datagram).
- ✅ **Retry / address validation** (RFC 9000 §8.1, §17.2.5; RFC 9001 §5.8): server optionally
  behind `requireRetry`/`--retry` — responds to the first tokenless Initial with a `RetryPacket`
  (integrity tag over the ODCID), validates the echoed token. The client verifies the tag,
  re-derives the Initial keys from the Retry SCID (RFC 9001 §5.2), resends the ClientHello with the
  token. `retry_source_connection_id` TP added. **Confirmed live over UDP** (H3Get "after Retry").
  Fixed a real bug along the way: tiny 1-RTT packets need PADDING for the HP sample
  (RFC 9001 §5.4.2, `PacketPadding`).
- ✅ **Connection close & draining** (RFC 9000 §10.2): `Close(TransportError, reason)` sends a
  CONNECTION_CLOSE and enters the closing state (only CONNECTION_CLOSE from then on, re-sent per
  incoming packet); receiving a CONNECTION_CLOSE → draining (sends nothing more, records
  `PeerCloseFrame`); after 3·PTO → closed. `IsClosing`/`IsDraining`/`IsClosed` passed through;
  H3Get closes down properly after the GET, H3Server detects/reaps draining connections.
  **Confirmed live over UDP.**
- ✅ **Connection-ID rotation** (RFC 9000 §5.1, §19.15/§19.16): `ConnectionIdManager` manages the
  locally issued (peer→DCID) and the peer-offered (us→DCID) connection IDs with sequence numbers.
  `IssueConnectionId()` sends NEW_CONNECTION_ID (respects `active_connection_id_limit`);
  `RotateDestinationConnectionId()` switches the DCID and retires the old one via
  RETIRE_CONNECTION_ID; "Retire Prior To" and incoming RETIRE are handled. Receiving only accepts
  packets to an active local CID. **Confirmed live over UDP** (our own server issues a CID, the
  client rotates → 2nd GET under the new CID). Cloudflare offered no additional CID in the short
  connection (server policy).
- ✅ **Stateless reset** (RFC 9000 §10.3), **receive + send**:
  - **Receive:** the peer's tokens (from NEW_CONNECTION_ID + the `stateless_reset_token` TP) are
    stored; a non-processable short-header datagram whose last 16 bytes match a known token
    (constant-time) leads to draining (`StatelessResetReceived`).
  - **Send:** the server now derives its tokens from the CID (`StatelessResetTokenGenerator` =
    HMAC-SHA256(secret, CID)[0..16], §10.3.1), so they are recomputable after state loss. The demux
    (H3Server) answers a 1-RTT packet for an **unknown** DCID with `StatelessReset.BuildResponse`:
    compute the token from the DCID, build a reset **smaller** than the trigger (loop avoidance
    §10.3.3), only for short headers above a minimum size. Tested in-process end-to-end (stateless
    responder with shared secret ⇒ reset which the client recognises) + unit tests (token
    determinism, size/loop rules). The H3Server **persists the secret** (`--secret-file=`, default
    next to the exe) ⇒ identical across restarts (verified: identical bytes, "loaded"), so a
    restarted server can send valid resets for old connections. The demux only opens new
    connections for genuine **Initial** packets (RFC 9000 §5.2); short header to unknown CID ⇒
    reset, other long headers ⇒ dropped. (A live cross-restart demo is not included: the sample's
    single-socket client flushes a stale Initial instead of a 1-RTT packet on target switch — a
    sample-orchestration limit, not a question of the protocol logic.)
- ✅ **Discarding keys after the handshake** (RFC 9001 §4.9.1/§4.9.2): the endpoint discards the
  **Initial** keys (client: as soon as it has sent a Handshake packet; server: as soon as it has
  processed one) and the **Handshake** keys (once the handshake is confirmed). **Handshake
  confirmation** (§4.1.2): server at completion; client at HANDSHAKE_DONE **or** — additionally,
  RFC-legitimate (MAY) — as soon as one of its **1-RTT packets is acknowledged**
  (`OnOneRttPacketAcknowledged`, compared against the first 1-RTT PN). This way the Handshake keys
  may be discarded even before a lost HANDSHAKE_DONE (more robust). `DiscardKeys` clears keys,
  pending CRYPTO/retransmits and the loss-recovery space (RFC 9002 §6.4, bytes out of
  `bytes_in_flight`). **Fixes a bug:** without the discard, a PTO probed the Initial space and
  resent the ClientHello after the handshake as a (padded) 1200-byte Initial.
  Test `KeyDiscardTests` (after the handshake, under PTO, no Initial/Handshake packet); Cloudflare
  live (normal, `--mlkem`, `--zerortt`) status 200 each. **Timing checked against RFC 9001 §4.9.1:**
  the discard points are exactly the prescribed ones; **earlier would violate the RFC** (§4.9: the
  peer would not have "done the same", and the Initial keys are still needed to ack the peer's
  Initial) and would gain nothing (ACK + Finished in the same flight). A second test secures the
  other direction (the client sends the Initial ACK of the ServerHello ⇒ ≥2 Initial packets, so not
  discarded too early). **Reordering window checked against RFC 9001 §4.9.2:** the Handshake keys
  are discarded **immediately** on confirmation, **without** a short retention for reordered
  packets. That is the RFC's intent: §4.9.2 is an unconditional MUST **without** a reordering
  clause, while §4.9.3 grants such a window (~3×PTO) **only for 0-RTT** — there the sender still
  produces real app data that can reorder; after handshake confirmation a late Handshake packet
  would only carry already-known information (§4.9: new data at the highest level, below only
  ACK/CRYPTO retransmit). Test
  `HandshakeKeys_DiscardedImmediatelyOnConfirmation_NoReorderingWindow` (keys gone at the very
  moment of confirmation).
- ✅ **Key update** (RFC 9001 §6): `TrafficKeys.Next` derives `secret_<n+1>` via "quic ku" (key/IV
  new, **HP key unchanged**); `PacketProtection.RemoveHeaderProtection` separates HP from AEAD so
  the key-phase bit is read before key selection. `InitiateKeyUpdate()` rotates the send keys and
  flips the phase; a flipped bit on receive rotates read (and possibly send) keys; previous read
  keys are kept briefly for reordering. `CurrentKeyPhase`/`KeyUpdateCount` passed through.
  **Confirmed live against cloudflare-quic.com** (second GET under rotated keys,
  `H3Get --key-update`).
- ✅ **Transport-error matrix** (RFC 9000 §11/§20.1) — COMPLETE: protocol violations by the peer →
  CONNECTION_CLOSE with the correct error code instead of crash/silence. FRAME_ENCODING_ERROR
  (encoding/unknown errors during frame parsing), STREAM_LIMIT_ERROR, stream-level
  FLOW_CONTROL_ERROR and FINAL_SIZE_ERROR (from `StreamReceiveBuffer`), STREAM_STATE_ERROR
  (RESET_STREAM/STOP_SENDING on wrong stream kinds, §19.4/§19.5). Along the way
  **PATH_CHALLENGE/PATH_RESPONSE** (§19.17/§19.18) — needed live against Cloudflare.
  - ✅ **Connection-level FLOW_CONTROL_ERROR** (§4.1): the sum of the highest received offsets of
    ALL streams (with RESET the final size counts, §4.5) is checked after every STREAM/RESET frame
    against the connection window granted via initial_max_data/MAX_DATA. Tested end-to-end (test
    seam `OverrideConnSendLimitForTest` overrides the well-behaved client) + counter-check within
    the window.
  - ✅ **TRANSPORT_PARAMETER_ERROR** (§7.3/§7.4/§18.2): `TryDecode` rejects — duplicate IDs (even
    unknown ones), max_udp_payload_size < 1200, active_connection_id_limit < 2, stream limits
    > 2^60, stateless_reset_token ≠ 16 B, CIDs > 20 B (previously the ConnectionId ctor threw
    here — a fuzzer find!). **§7.3 authentication** via `ValidatePeerTransportParameters`
    (endpoint + role overrides): initial_source_connection_id mandatory + == peer SCID; the client
    checks original_destination_connection_id (mandatory + == first DCID) and
    retry_source_connection_id (EXACTLY on Retry, == Retry SCID); the server rejects server-only
    parameters from the client (ODCID/RSCID/stateless_reset_token/preferred_address).
    End-to-end: "evil" client with ODCID ⇒ server closes 0x08, the client reads the close.
  - ✅ **CONNECTION_CLOSE delivery during the handshake repaired** (§10.2.3, found by the new test):
    before handshake confirmation the close went out only at the highest level (possibly 1-RTT) — a
    peer with only Initial keys could NEVER read it. Now: a 1-RTT close only after confirmation,
    before that coalesced Initial+Handshake (fallback 1-RTT when the long-header keys are already
    discarded).
  - ✅ **Parser fuzzer** (deterministic, fixed seeds ⇒ reproducible): FrameParser,
    TransportParameters and the packet-header parsers NEVER throw on random AND mutated valid bytes
    (bit flips/truncations) — errors surface as clean false/EncodingError. 4 fuzz runs of
    2000–4000 iterations each.
  - 11 new tests (TransportErrorMatrixTests + ParserFuzzTests). **Live:** Cloudflare GET + 0-RTT,
    our own server with --retry (RSCID path) and curl --http3 pass regression-free with the strict
    checks.
- ✅ **RESET_STREAM / STOP_SENDING** (RFC 9000 §2.4, §3.5, §19.4/§19.5): `QuicStream.Reset(code)`
  aborts the send side (unsent data discarded, final size = bytes sent per §4.5, no further
  STREAM (re)transmissions afterwards); `AbortRead(code)` sends STOP_SENDING. Receive: RESET_STREAM
  validates the final size (§4.5, immutable; counts fully as flow-control credit) and marks the
  receive side (`IsResetByPeer`/`PeerResetErrorCode`, never "complete"); STOP_SENDING automatically
  resets our own send side with the copied error code (§3.5 MUST). Both frame types run reliably
  through loss recovery (tracked as retransmittable; loss test via dropped flight + PTO). Tested
  in-process (7 tests: buffer units, copied code end-to-end, state errors, HTTP/3 cancellation,
  loss).
- Grease: tolerate the peer's reserved frame/stream types.

### ✅ Phase 9 — Performance & nice-to-have — COMPLETED
*(0-RTT and the PQ/crypto extras are sorted here historically and have long been ✅; the async API,
the zero-allocation path, UDP batching and window auto-tuning likewise.)*
- ✅ **Zero-allocation path (hot paths)**: replaced the per-pump-pass expensive `List<byte>` buffers
  (whose `RemoveRange(0, n)` shifted ALL remaining bytes on every consume — O(n²) over a transfer —
  and whose `ToArray()` copied the whole content per pass) with **`ByteQueue`** (Quic.Core:
  head/tail ring buffer, amortised O(1) append/consume, backing store reused, read-out as
  `Span`/`Memory` without copying). Affected: `StreamSendBuffer` plus all HTTP/3
  stream/capsule/QPACK uni-stream buffers in `Http3ClientConnection`/`Http3ServerConnection`/
  `Http3Qpack`. `StreamReceiveBuffer.ReadAvailable` now builds the result in ONE pre-sized array
  (no `MemoryStream`) and has an allocation-free empty fast path. **Measurement** (in-process,
  `GC.GetAllocatedBytesForCurrentThread`, single-threaded ⇒ exact): 300 KB download reduced from
  **51.3 MiB to 7.0 MiB** (7.3×; ~25 instead of 179 B per payload byte), time ~55 → ~40 ms.
  Measurement harness `PerformanceBenchTests` with a generous regression guard (download < 20 MiB).
- ✅ **UDP batching (GSO)**: `GsoBatcher` (Quic.Core) groups the datagrams of one pump pass into
  UDP_SEGMENT batches — maximal run of equal-sized datagrams, optionally plus one smaller final
  segment (the kernel rule), capped at 64 segments / 65535 B. `UdpBatchSender` (Http3) sends each
  batch on **Linux** with a single `sendmsg` (socket option UDP_SEGMENT via `SetRawSocketOption`,
  best-effort with fallback on rejection), on all other platforms a lean single-send loop —
  identical on the wire, GSO only saves syscalls. Used by the async facades
  `Http3Client`/`Http3Server`. The pure grouping is tested deterministically (reconstruction =
  original datagram sequence, segment/byte caps).
- ✅ **Window auto-tuning (receive-side flow-control windows per BDP)**: a fixed window throttles a
  fast connection to ≈ window/RTT — the BDP grows with the RTT. `ReceiveWindowTuner` (Quic.Streams)
  applies the Chromium/quiche heuristic: at EVERY due window update (credit below half the window)
  the time since the last update is measured; if it is < 2×SmoothedRtt, the sender was at the
  window edge faster than one RTT ⇒ double the window (up to 16 MiB per stream / 24 MiB per
  connection). Wired into `CollectFlowControlFrames` — per stream
  (`StreamReceiveBuffer.WindowTuner`) and for the connection window (`_connWindowTuner`); starting
  values remain the configured initial_max_data*. 5 tests (heuristic: growth on fast/no growth on
  slow drainage, capping, limit ≥ starting value; QUIC end-to-end: connection window grows under
  sustained transfer). **Live:** Cloudflare GET also with `--small` (48 KiB starting window) over
  real RTT, curl 200 KB POST upload echoed byte-exactly.
- ✅ **async API — Task-based facades over real sockets** (`src/Http3/Http3Client.cs` /
  `Http3Server.cs`): the deterministic, transport-agnostic core remains untouched (all tests still
  synchronous in-process); on top, the facades own the UDP socket and a background pump
  (ReceiveAsync + 20 ms timer tick, Task.WhenAny).
  - **Client** `Http3Client`: `ConnectAsync` (handshake + InitializeHttp3, TimeoutException instead
    of hanging; SIO_UDP_CONNRESET disabled on Windows), `SendAsync`/`GetAsync`/`PostAsync`
    (request → `Task<Http3Response>`; final failures as `Http3RequestException` with `IsRetryable`
    for GOAWAY rejections; CancellationToken ⇒ §4.1.1 cancellation), `PerformAsync`/`QueryAsync`/
    `WaitUntilAsync` (serialised access for datagrams/WebTransport/CONNECT), `CloseAsync`
    (graceful), `DisposeAsync`. Core accesses strictly serialised via a SemaphoreSlim.
  - **Server** `Http3Server`: binds the socket (port 0 = ephemeral, `Port` property), demuxes
    primarily via the connection ID (migration hits the same connection), new connections ONLY on
    genuine Initial packets (§5.2), optional stateless reset for unknown short headers (§10.3),
    idle cleanup; fully configurable via a `Func<Http3ServerConnection>` factory (WebTransport &
    co. included).
  - 5 tests (Http3AsyncApiTests) over REAL loopback UDP sockets: GET, three parallel requests on
    one connection, POST echo, timeout against a dead port, Query/WaitUntil.
- ✅ **0-RTT (RFC 8446 §2.3 / RFC 9001 §4) — complete**:
  - **Phase A — session resumption (PSK)**: NewSessionTicket (issuing + parsing),
    resumption_master_secret / resumption PSK, `pre_shared_key` with **binder** (HMAC over the
    truncated ClientHello, RFC 8446 §4.2.11.2), `psk_key_exchange_modes` (always sent ⇒ the server
    issues tickets), server-side ticket store + binder verification, handshake without certificate.
  - **Phase B — early data**: `early_data` extension (ClientHello + EncryptedExtensions
    confirmation), `client_early_traffic_secret`, its own **0-RTT key set** (in the application PN
    space), **0-RTT packets** (long header 0x01) — the client sends the HTTP/3 request as early
    data **before** handshake completion, the server accepts and processes it. Byte-exact interop
    **live against cloudflare-quic.com** (`H3Get --zerortt` → "0-RTT ACCEPTED", 126 KB, status 200)
    plus our own server over UDP + an in-process test.
    **Discarding 0-RTT keys** (RFC 9001 §4.9.3): the client discards its 0-RTT key set as soon as
    the 1-RTT keys are installed (`MaybeInstallApplicationKeys`, client only) — after that it sends
    no more 0-RTT packets (§5.6) and never receives any itself, the keys are useless; immediate
    discarding minimises the attack window. Test `Client_DiscardsZeroRttKeys_OnInstallingOneRttKeys`.
    **Reordering checked:** on the client there is deliberately **no** retention window for this
    (§4.9.3 "no use after that moment"): it has no 0-RTT read path — reordered/late packets are
    unprotected with Initial/Handshake/1-RTT read keys, and lost 0-RTT data travels over 1-RTT
    (application retransmit queue), never again as 0-RTT. Only the **server** (receiver) needs the
    short window.
    The **server** discards its 0-RTT read keys with a different trigger: it keeps them briefly
    after the **first received 1-RTT packet** (genuine short header ⇒ `DeliverApplicationFrames`)
    for reordered 0-RTT packets and then discards them "within a short time", RECOMMENDED **3×PTO**
    (`MaybeDiscardServerZeroRttKeys`, purely time-driven — triggered via
    `CheckLossDetectionTimeout` even without further traffic).
    **Earlier discarding on complete receipt** (§4.9.3 last sentence, "A server MAY discard 0-RTT
    keys earlier if it determines that it has received all 0-RTT packets, … by keeping track of
    missing packet numbers"): if the application packet numbers from 0 are **gap-free**
    (`PacketNumberSpace.IsContiguousFromZero`, i.e. `Count = Max+1`) and a 1-RTT packet has already
    been received (upper bound of the 0-RTT PNs known, since 0-RTT PNs all lie below it), no
    reordered 0-RTT packet can still be outstanding ⇒ `MaybeDiscardServerZeroRttKeysIfComplete`
    discards immediately without waiting out the 3×PTO deadline. Checked at every received
    application packet (1-RTT via `DeliverApplicationFrames`, reordered 0-RTT via
    `DecryptAndHandle`). Tests
    `Server_DiscardsZeroRttKeysEarly_WhenAllPacketsReceived_NoGap` (loss-free ⇒ gone immediately
    despite a 5-min deadline) and
    `Server_RetainsZeroRttKeys_UntilTimeout_WhenPacketNumberGapPersists` (PN gap ⇒ fallback to the
    deadline). **Connection end:** if the connection ends before the 0-RTT read keys were regularly
    discarded (short-lived connection before deadline/gap-freeness), `Dispose()` releases them
    (fixed: they were missing from the key release next to
    `WriteKeys`/`ReadKeys`/`_nextAppReadKeys`/`_prevAppReadKeys`). Test
    `Server_DiscardsZeroRttKeys_OnDispose`.
  - **0-RTT rejection → 1-RTT retry** (RFC 9001 §4.6.2): because 0-RTT lives in the application PN
    space, normal loss recovery already applies (never-acknowledged 0-RTT packets ⇒ frames
    retransmitted over 1-RTT). Additionally **proactive**: when the client detects the rejection
    (no early_data in EE), it immediately moves the 0-RTT frames into the 1-RTT retransmit queue
    (`LossRecovery.OnZeroRttRejected`) without waiting for time threshold/PTO and without
    double-sending. In-process test (server rejects ⇒ the request still passes over 1-RTT,
    status 200). **Handshake keys after 0-RTT rejection checked** (RFC 9001 §4.9.2 + §4.1.2): the
    Handshake key discard stays correct although 0-RTT and 1-RTT share the same application PN
    space. The §4.1.2 confirmation (via 1-RTT ACK) counts only a **genuine** 1-RTT packet:
    `_firstOneRttPacketNumber` is set exclusively in `BuildApplicationPackets` (never in
    `BuildZeroRttPackets`), and since 0-RTT PNs are always smaller, `LargestAck ≥` that PN provably
    implies acknowledgment of a 1-RTT packet — an (accepted or stray) 0-RTT ACK never confirms the
    handshake too early. No behaviour change needed; regression test
    `RejectedEarlyData_HandshakeStillConfirmsAndDiscardsHandshakeKeys_ViaOneRttAck` (0-RTT rejected
    AND HANDSHAKE_DONE suppressed ⇒ the client confirms via 1-RTT ACK and discards the Handshake
    keys).
- ✅ **ECN** (RFC 9000 §13.4 / RFC 9002 §7.3): the receiver counts the ECN codepoints (ECT0/ECT1/CE)
  per packet-number space (`PacketNumberSpace.RecordReceived(pn, ecn)`) and reports them in the ACK
  frame (type 0x03, was already serialisable). The sender treats an increased CE counter like a
  loss and halves the window (`LossRecovery` ProcessECN → `NewReno.OnEcnCongestionEvent`, only once
  per recovery period). The codepoint is passed through via `ProcessDatagram(dg, ecn)`. Tested
  in-process (counting/reporting, CE reaction, end-to-end cwnd decrease). **Limit:** the actual
  IP-level marking (setting ECT/reading CE) is not practicable with BCL UDP sockets — especially on
  Windows (IP_TOS restricted); that is pure transport layer, the protocol logic is complete.
- ✅ Crypto roadmap **complete**: X25519, X448, ChaCha20-Poly1305, Ed25519, Ed448 (primitives from
  BouncyCastle) **and** the PQ hybrid X25519MLKEM768 (ML-KEM from the BCL + X25519) — confirmed
  live/interop.
- ✅ **ML-DSA signatures (FIPS 204, draft-ietf-tls-mldsa)** — post-quantum server certificates,
  completely BCL-native (.NET 10 `MLDsa` + `CertificateRequest`; X509 PQC APIs selectively via a
  SYSLIB5006 pragma): SignatureSchemes mldsa44/65/87 (0x0904–0x0906, pure, FIPS 204 context
  empty — §4), `ServerCertificate.CreateSelfSignedMLDsa` (default ML-DSA-65), the client verifies
  CertificateVerify incl. a parameter-strength check (SPKI OID 2.16.840.1.101.3.4.3.17/.18/.19 must
  match the scheme) and offers the three schemes in signature_algorithms. 2 tests (handshake + all
  three parameter sets; `MLDsa.IsSupported` guard). **Live over UDP:** `H3Server --mldsa` +
  `H3Get -k` → status 200; and **fully post-quantum** `--mldsa --mlkem` on both sides:
  X25519MLKEM768 KEX + ML-DSA-65 signature → 200.
- ✅ **Connection migration** (RFC 9000 §8.2/§9): path validation (`InitiatePathValidation` sends
  PATH_CHALLENGE with 8 random bytes, matching PATH_RESPONSE → `PathValidated`, with a 3·PTO
  deadline); PATH_CHALLENGE is answered. `OwnsConnectionId` allows CID-based demuxing. **Live over
  UDP:** H3Server demuxes via the connection ID; `H3Get --migrate` switches the local port → the
  server detects the migration, validates the new path, the second GET passes over the new path.
  Tested in-process (client/server-initiated + expiry).
- ✅ **Anti-amplification limit** (RFC 9000 §8.1): before address validation the server sends at
  most 3× as many bytes as it has received (`_amplificationReceived/_amplificationSent`, budget
  passed to `BuildLevelPacket`; CRYPTO stays persistently buffered if the budget defers it).
  Validated at the first decrypted Handshake packet or a valid Retry token; the client is validated
  by construction. Tested in-process (invariant sent ≤ 3×received), live green (our own server
  under the limit, Cloudflare/`--loss` unaffected).

---

## Test & debug strategy (from the start!)

1. **RFC test vectors as unit tests:** RFC 9001 Appendix A (Initial packets, Retry tag,
   ChaCha20 vectors), RFC 8448 (TLS key schedule), RFC 7541 Appendix C (Huffman).
2. Implement **`SSLKEYLOGFILE` export** → Wireshark can decrypt our own QUIC packets.
   Priceless for debugging; ~30 lines of code.
3. Build in **qlog** (JSON event log per connection) early → visualisation with qvis.
   At minimum: packet_sent/received, frames, loss, recovery metrics.
4. **Lossy UDP proxy** in the test project (drop/reorder/duplicate/delay configurable,
   seed-based deterministic) for recovery tests without external tools.
5. **Interop targets (client side) ✅ 8 stacks:** quiche (Cloudflare), nginx, Google QUIC, mvfst
   (Meta), lsquic (LiteSpeed), msquic (Microsoft/outlook), quic-go (Caddy), Akamai — each status
   2xx/3xx with full cert validation. **Server side:** `curl --http3` ✅ (ngtcp2/LibreSSL on
   Windows + OpenSSL-QUIC under WSL/Debian); Firefox/Chrome open (need trusted certificates).
6. **State-machine tests in-process:** our own client against our own server without a real
   network (in-memory "UDP"), so handshake tests run in milliseconds.

## Crypto roadmap

Staged by interop benefit and effort.

**Principle (important):** "from scratch" means the **protocol logic**, not the crypto primitives.
We build QUIC/TLS handshake/QPACK/HTTP/3 ourselves and call vetted, constant-time implementations
for primitives — the BCL for AES/P-256, a lean, audited library for the BCL gaps (X25519/Ed25519).
**Writing curve arithmetic or cipher rounds with secret-dependent table lookups ourselves is
expressly unwanted** (side-channel/security risk, and not the learning goal of the project).
**One deliberate exception:** the raw ChaCha20 block for header protection
(see crypto roadmap stage 2.3) — ARX/constant-time without table lookups, and the libraries offer
no single block at an arbitrary counter, which RFC 9001 §5.4.4 requires.
Everything behind the abstractions (`IPacketProtection`, key-exchange/signature interfaces) so the
transport code never sees the source and it stays swappable.

Library options for the primitive gaps (v2), weighed pragmatically:
- **BouncyCastle.Cryptography** — purely managed, covers X25519/Ed25519/ChaCha20/Ed448/X448; one
  dependency, but large. Use only the primitives, **not** the TLS stack.
- **libsodium/NSec** — native, very fast and widely audited; for X25519/Ed25519/ChaCha20.
- Stays usable as a test oracle: RFC vectors can be cross-checked against the primitives.

**Stage 1 — v1, mandatory (pure BCL):** ✅ complete
- ✅ AEAD: AES-128-GCM (`AesGcm`); AES-256-GCM (`TrafficKeys` parameterised)
- ✅ Key exchange: `secp256r1` (P-256) via `ECDiffieHellman` (`EcdheKeyExchange`)
- ✅ Signatures: RSA-PSS, ECDSA P-256/P-384 — CertificateVerify is ALWAYS verified (phase 2),
  chain + hostname per `CertificateValidationOptions`
- → covers 100 % of real HTTP/3 servers

**Stage 2 — v2, extras (primitives from a library + BCL PQ):**
1. ✅ **X25519** (RFC 7748) — primitive from BouncyCastle (`X25519KeyExchange`), encapsulated
   behind `IKeyExchange`. The client offers X25519 first; **agreed on X25519 live against
   cloudflare-quic.com**. HelloRetryRequest (client + server) implemented and tested in-process.
2. ✅ **X25519MLKEM768** (hybrid PQ key exchange, codepoint 0x11EC/4588, draft-ietf-tls-ecdhe-mlkem) —
   **ML-KEM-768 from the BCL** (`MLKem` in .NET 10, stable, no experimental warning), X25519 from
   BouncyCastle. We write the **hybrid combination** ourselves (protocol logic): client share
   ek(1184)‖x25519(32)=1216, server share ct(1088)‖x25519(32)=1120, secret
   ss_mlkem(32)‖ss_x25519(32)=64 — **ML-KEM part first** (the historical "reversed" quirk for
   X25519MLKEM768). Since a KEM is asymmetric (server encapsulates, client decapsulates),
   `IKeyExchange` got an `Encapsulate` method (default = classic DH). In-process handshake green;
   **live over UDP against our own server (`--mlkem`) and byte-exact interop against
   cloudflare-quic.com** (group X25519MlKem768, full chain, status 200, 126 KB) — a wrong byte
   order would have broken the Finished MAC. Motivation: "harvest now, decrypt later";
   Chrome/Firefox/Cloudflare have run the hybrid since 2024/25.
3. ✅ **ChaCha20-Poly1305** — `ChaCha20Poly1305` (BCL) for AEAD; the raw ChaCha20 block for header
   protection is **deliberately hand-written** (`Crypto/ChaCha20.cs`). Rationale: the BCL and
   BouncyCastle alike offer ChaCha20 only as a *stream/AEAD* cipher (counter starts at 0), but
   RFC 9001 §5.4.4 needs a *single block at an arbitrary 32-bit counter* (from the sample) — there
   is no clean API call for that. The side-channel argument for the other library primitives hardly
   applies here: ChaCha20 is ARX (add-rotate-xor), constant-time by construction, without
   secret-dependent table lookups (unlike AES S-boxes or X25519 field arithmetic). The block is
   verified byte-exactly against RFC 8439 §2.3.2 and RFC 9001 §A.5 (`aefefe7d03`) and confirmed live.
4. ✅ **Ed25519** (RFC 8032) — signatures; primitive from BouncyCastle (`Ed25519Signature`),
   encapsulated like X25519. `SignatureScheme ed25519` (0x0807) is offered in the ClientHello and
   verified client-side (PureEdDSA, no pre-hash; public key from the leaf SPKI).
   `ServerCertificate` can generate a self-signed Ed25519 certificate (key/signature from
   BouncyCastle, TBSCertificate built via a BCL `X509SignatureGenerator`). RFC 8032 §7.1 byte-exact
   (public key + signature, tests 1+2); in-process handshake with an Ed25519 cert green, and
   confirmed live over UDP (`H3Server --ed25519` + `H3Get -k` → signature verified, status 200).
   Barely present in the WebPKI, hence an extra.

**Stage 3 — optional (completeness):**
- ✅ **X448** (RFC 7748, Curve448/"Goldilocks"): primitive from BouncyCastle (`X448KeyExchange`,
  behind `IKeyExchange` like X25519), named group `x448` (0x001e), 56-byte key/secret.
  `KeyExchange.Create`/`IsSupported` know X448; the named groups are now threaded through the whole
  API (`Http3ClientConnection` `keyExchangeGroups`, `Http3ServerConnection` `preferredGroups`).
  RFC 7748 §5.2 byte-exact (both single vectors), the in-process handshake agrees on X448, and
  confirmed live over UDP (`H3Server --x448` + `H3Get --x448 -k` → group X448, status 200).
  Practically absent in the field (browsers don't offer x448), hence pure completeness.
- ✅ **Ed448** (RFC 8032, edwards448/SHAKE256): signature primitive from BouncyCastle
  (`Ed448Signature`, encapsulated like Ed25519), `SignatureScheme ed448` (0x0808), PureEdDSA with an
  **empty context** (TLS 1.3), public key 57 bytes / signature 114 bytes. The client verifies the
  CertificateVerify signature (public key from the leaf SPKI, id-Ed448 1.3.101.113);
  `ServerCertificate.CreateSelfSignedEd448` builds an Ed448 certificate via the same
  `X509SignatureGenerator` path as Ed25519. RFC 8032 §7.4 byte-exact (public key + signature,
  blank + 1-octet); in-process handshake with an Ed448 cert green, and confirmed live over UDP
  (`H3Server --ed448` + `H3Get -k` → signature verified, status 200). Not found in the field
  (the WebPKI issues no Ed448 certificates), hence pure completeness.
- **PQ signatures (ML-DSA/SLH-DSA)**: `MLDsa`/`SlhDsa`/`CompositeMLDsa` are already present in
  .NET 10 — usable once the WebPKI issues PQ certificates. Watch until then.

**Design note:** put crypto calls in the QUIC layer behind a narrow interface
(`IPacketProtection`: Seal/Open/HeaderMask; analogous for key exchange and signatures) so that
new suites/groups are pluggable without changes to the transport code.

## Deliberate omissions (scope control)

*(Historical v1 omissions since retrofitted: ChaCha20-Poly1305, X25519/X448/hybrid PQ, 0-RTT and
the dynamic QPACK table have long been implemented — see the crypto roadmap and phases 6/9.
Likewise ALL HTTP/3 extensions: Priorities (9218), WebSockets (9220), HTTP datagrams (9297/9221),
WebTransport (draft-13) — see phase 7.)*

- **No** server push (MAY; PUSH frames/streams are rejected with validation), **no** classic
  CONNECT proxying (valid CONNECT without :protocol ⇒ 501).
- **No** CUBIC/BBR (NewReno suffices), **no** multipath extension.
- No HTTP/1.1/2 fallback, no Alt-Svc handling — pure HTTP/3.
- WebTransport (draft-13) is meanwhile FULLY implemented — including the once-open edge pieces
  RESET_STREAM_AT, WT protocol negotiation (§3.3) and the keying-material exporter (§4.7), see
  phase 7.

## Recommended order of the first steps

1. ✅ Phase 0 + VarInt with tests (half a day).
2. ✅ Get the RFC 9001 Appendix A vectors running (Initial secrets, AEAD, header protection) —
   with that, the whole crypto foundation stands provably correct.
3. ✅ Build the ClientHello, send an Initial packet to cloudflare-quic.com, parse the ServerHello —
   from here on, every step gets real server feedback instead of dry runs.

**Next (as of 2026-07-23):** ALL phases (0–9) are complete — RFC 9114 feature audit,
transport-error matrix, all extensions (Priorities/WebSockets/datagrams/WebTransport complete incl.
RESET_STREAM_AT), PQ crypto (ML-KEM hybrid + ML-DSA), async API, curl interop and the performance
extras (zero-alloc, UDP batching/GSO, window auto-tuning). Client interop is confirmed against
**8 independent QUIC stacks** (quiche/nginx/Google/mvfst/lsquic/msquic/quic-go/Akamai — matrix at
M2). Remaining extras: browser interop (Firefox/Chrome, need trusted certificates) or the
migration back into Hermod (deduplicating the WebSocket copies).

## References

- RFC 9000 — QUIC: Transport
- RFC 9001 — Using TLS to Secure QUIC (incl. test vectors in Appendix A)
- RFC 9002 — QUIC Loss Detection and Congestion Control
- RFC 8446 — TLS 1.3 (+ RFC 8448 example traces)
- RFC 9114 — HTTP/3
- RFC 9204 — QPACK (+ RFC 7541 Appendix B: Huffman table)
- RFC 9369 — QUIC Version 2 (for awareness only; v1 suffices)
- Reference implementations for lookup (not as dependencies!):
  quiche (Cloudflare, Rust), ngtcp2 (C), quic-go (Go), msquic (C).
