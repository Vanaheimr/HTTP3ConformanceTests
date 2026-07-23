# HTTP/3 from Scratch — Implementierungsplan

**Ziel:** Ein vollständiger HTTP/3-Stack (Client + Server) in C# auf .NET 10, direkt auf UDP-Sockets
aufsetzend. Keine externen Abhängigkeiten — nur die BCL (`System.Net.Sockets`,
`System.Security.Cryptography`, `System.Buffers`).

**Realität vorab:** „HTTP/3 from scratch" bedeutet faktisch „QUIC + TLS 1.3 from scratch".
HTTP/3 (RFC 9114) selbst ist die kleinste Schicht. Der Löwenanteil der Arbeit ist:

| Schicht | RFC | Anteil (grob) |
|---|---|---|
| QUIC Transport (Streams, Frames, State Machine) | RFC 9000 | ~35 % |
| TLS 1.3 Handshake (ohne Record Layer) | RFC 8446 + RFC 9001 | ~25 % |
| Loss Detection & Congestion Control | RFC 9002 | ~15 % |
| QPACK Header-Kompression | RFC 9204 | ~10 % |
| HTTP/3 Framing & Semantik | RFC 9114 | ~10 % |
| UDP-I/O, Buffer-Management, Tooling | — | ~5 % |

Wichtig: QUIC nutzt **keinen** TLS-Record-Layer. Die TLS-Handshake-Nachrichten
(ClientHello, ServerHello, …) werden in QUIC-**CRYPTO-Frames** transportiert; QUIC übernimmt
selbst die Verschlüsselung der Pakete mit den von TLS abgeleiteten Schlüsseln. Wir brauchen
also eine TLS-1.3-**Handshake-Engine**, aber keinen kompletten TLS-Stack.

---

## Verfügbare .NET-Bausteine (und Lücken)

**Vorhanden (BCL, keine „große Abhängigkeit"):**
- `Socket` (UDP, `ReceiveFromAsync`/`SendToAsync`, `SocketAddress` für allokationsfreies I/O)
- `AesGcm` — AEAD für Packet Protection (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384)
- `Aes.EncryptEcb` — Header Protection (AES-basiert)
- `HKDF` (Extract/Expand) — Key Schedule; `HKDF-Expand-Label` schreiben wir als dünnen Wrapper
- `ECDiffieHellman` (P-256/P-384) — Schlüsselaustausch
- `SHA256`/`SHA384`, `IncrementalHash` — Transcript-Hash
- `RSA` (PSS), `ECDsa` — CertificateVerify-Signaturen prüfen/erstellen
- `X509Certificate2`, `X509Chain`, `CertificateRequest` — Zertifikate (inkl. Self-Signed für Tests)

**Lücken (in .NET 10 per Reflection geprüft):**
- **X25519 / Ed25519 / X448 / Ed448**: in der BCL **nicht** vorhanden. ✅ **Alle vier** kommen aus
  BouncyCastle (`BouncyCastle.Cryptography`) — die einzige externe Krypto-Dependency: X25519 + X448 hinter
  `IKeyExchange`, Ed25519 + Ed448 als `Ed25519Signature`/`Ed448Signature`, jeweils nur für das Primitiv gekapselt.
- **ChaCha20 (raw)**: `ChaCha20Poly1305` ist vorhanden (AEAD), aber Header Protection braucht den
  rohen ChaCha20-Block. ✅ **Erledigt:** eigener konstant-zeitiger ChaCha20-Block (`Crypto/ChaCha20.cs`,
  RFC 8439 §2.3) für die HP-Maske; die AEAD kommt weiter aus der BCL. `TLS_CHACHA20_POLY1305_SHA256`
  wird ausgehandelt (Client-Angebot + Server-Präferenz) und ist live gegen Cloudflare bestätigt.
- **Vorhanden & überraschend nützlich (.NET 10):** die komplette PQC-Familie `MLKem`, `MLDsa`
  (inkl. `CompositeMLDsa`), `SlhDsa` — der PQ-KEM-Anteil ist damit BCL-nativ.
- **Selbst schreiben wir nur die Protokoll-Logik:** QUIC, TLS-1.3-Handshake, QPACK, HTTP/3 —
  **nicht** die Krypto-Primitive.

---

## Projektstruktur

```
HTTP3FromScratch.slnx
src/
  Quic.Core/             # Gemeinsame Primitive – von allen Schichten genutzt
    VarInt.cs            # QUIC Variable-Length Integers (RFC 9000 §16)
    Buffers/             # BufferReader/BufferWriter über Span<byte>
  Quic.Tls/              # QUIC-TLS-Handshake-Bindung (RFC 8446 + 9001) – TLS 1.3 im QUIC-Profil,
                         # ohne Record-Layer; referenziert nur Quic.Core (kein Rückverweis auf Quic)
    Messages/            # ClientHello, ServerHello (+HRR), EE, Certificate(Verify), Finished, NST
    Crypto/              # KeySchedule, TlsHkdf, Transcript, IKeyExchange (ECDHE/X25519/X448/Hybrid-PQ), Ed25519/Ed448
    Handshake/           # TlsClientHandshake / TlsServerHandshake hinter ITlsHandshake, Zertifikatsprüfung
  Quic/                  # QUIC Transport (RFC 9000/9001/9002); referenziert Quic.Tls
    Packets/             # Long/Short Header, PN-Codec, Retry, VN, Stateless Reset, Connection ID
    Crypto/              # Initial Secrets, Packet/Header Protection (inkl. ChaCha20-HP), Key Update
    Frames/              # Alle Frame-Typen + FrameParser
    Connection/          # QuicEndpoint (gemeinsame Logik) + QuicClient-/QuicServerConnection, CID-Manager, Idle
    Streams/             # QuicStream, Send-/ReceiveBuffer, StreamId (inkl. Reset/AbortRead)
    Recovery/            # RTT, Loss Detection, PTO, NewReno, Pacer (RFC 9002)
  Http3.Qpack/           # QPACK (RFC 9204): Static Table, Huffman (RFC 7541 App. B, generiert),
                         # statischer + dynamischer Encoder/Decoder
  Http3/                 # HTTP/3 (RFC 9114) + Extensions + öffentliche API
    Http3ClientConnection.cs / Http3ServerConnection.cs
    Http3Client.cs / Http3Server.cs   # async API: Task-Fassaden mit Socket + Hintergrund-Pump
    UdpBatchSender.cs    # UDP-Batching: GSO (Linux) + Einzelsende-Fallback
    Http3Frame.cs / Http3Constants.cs / Http3Message.cs   # Frames, Fehlercodes, Request/Response
    Http3Qpack.cs        # QPACK-Anbindung + Uni-Stream-/Control-Stream-Zustandsmaschine
    Http3MessageValidator.cs  # Malformed-Erkennung (§4.1.2/§4.2/§4.3)
    Http3Priority.cs     # RFC 9218 (priority-Header/PRIORITY_UPDATE)
    Http3Tunnel.cs       # Extended-CONNECT-Tunnel (RFC 8441/9220)
    WebSocket/           # RFC-6455-Framing (Kopien aus Hermod.HTTP2, nur Namespace getauscht)
    WebTransport/        # WebTransport über HTTP/3 (draft-13): Session/Streams/Capsules/Manager
tests/
  Http3.Tests/           # 403 NUnit-Tests, u. a. mit RFC-Testvektoren und „bösen" Roh-QUIC-Peers
samples/
  H3Get/                 # HTTP/3-Client-CLI (GET/POST, Cancel, GOAWAY, 0-RTT, … — s. README)
  H3Server/              # Demo-Server über UDP (CID-Demux, Retry, Stateless Reset, GOAWAY, …)

Namespaces: org.GraphDefined.Vanaheimr.Hermod.Quic (+ .Tls/.Core/…) für den QUIC-Transport —
NEBEN, nicht unter HTTP/3; org.GraphDefined.Vanaheimr.Hermod.HTTP3 (+ .Qpack/.Tests) für die
HTTP/3-Schicht. Projekt-/Assemblynamen bleiben die kurzen. Usings in #region Usings-Blöcken.
```

---

## Phasen

**Status-Legende:** ✅ fertig · 🔶 teilweise · ⬜ offen. Stand: 403 Tests grün, Meilensteine M1–M3
erreicht (M1: Live-Handshake gegen cloudflare-quic.com · M2: echtes `GET` → Status 200 + 126 KB HTML ·
M3: eigener HTTP/3-Server, `H3Get`-Client holt Status 200 über echtes localhost-UDP).

### ✅ Phase 0 — Setup & Primitive (klein)
- ✅ Solution + Projekte anlegen, .NET 10, `net10.0`, Nullable, `AllowUnsafeBlocks` nur wo nötig.
- ✅ **VarInt** (RFC 9000 §16): Encode/Decode, 1/2/4/8 Bytes. Trivial, aber überall gebraucht.
- ✅ Span-basierte `BufferReader`/`BufferWriter`, `ArrayPool`-basiertes Buffer-Management.
- ✅ Unit-Test-Gerüst; ab Tag 1 gegen RFC-Testvektoren testen.

### ✅ Phase 1 — QUIC-Paketformate & Initial-Krypto (RFC 9000 §17, RFC 9001)
Ziel: Ein selbst gebautes Initial-Paket, das Wireshark korrekt dekodiert.
- ✅ Long Header (Initial, Handshake, 0-RTT, Retry) und Short Header (1-RTT) parsen/serialisieren.
- ✅ Connection IDs, Packet-Number-Encoding (verkürzte PN, Rekonstruktion beim Empfang).
- ✅ **Initial Secrets**: HKDF-Extract mit dem festen Salt der Version 1, dann
  `client in` / `server in` ableiten (RFC 9001 §5.2).
- ✅ **Packet Protection**: AEAD (AES-128-GCM **oder ChaCha20-Poly1305**) mit Nonce = IV XOR
  Packet Number; die Algorithmuswahl folgt der ausgehandelten Cipher-Suite (`AeadAlgorithm`).
- ✅ **Header Protection**: AES-ECB **bzw. roher ChaCha20-Block** über ein Sample des Ciphertexts,
  maskiert Flags + PN (RFC 9001 §5.4).
- ✅ **Prüfstein bestanden:** Die kompletten Testvektoren aus **RFC 9001 Appendix A** (Client
  Initial, Server Initial, Retry Integrity Tag) werden byte-genau reproduziert. Das ist der
  wertvollste Einzeltest des ganzen Projekts. **A.5 (ChaCha20 HP-Maske) inzwischen ebenfalls
  byte-genau** (`aefefe7d03`), plus RFC-8439-Blockvektor und ein Live-GET mit erzwungenem ChaCha20.

### ✅ Phase 2 — TLS-1.3-Handshake-Engine (RFC 8446, nur was QUIC braucht)
Ziel: Handshake-Nachrichten erzeugen/verarbeiten und den Key Schedule treiben.
- ✅ Nachrichten: ClientHello, ServerHello (+ HelloRetryRequest), EncryptedExtensions, Certificate,
  CertificateVerify, Finished — bauen und parsen. (Kein ChangeCipherSpec, keine Records — QUIC braucht das nicht.)
- ✅ Extensions: `supported_versions`, `key_share` (P-256), `signature_algorithms`, `server_name`,
  `supported_groups`, **`alpn`** (= `h3`, Pflicht!), **`quic_transport_parameters`** (RFC 9001 §8.2).
- ✅ Cipher Suites im ClientHello: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` angeboten
  (Server wählt AES-128-GCM). ✅ ECDHE P-256 (`EcdheKeyExchange`), gemeinsames Geheimnis ableitbar.
- ✅ **Key Schedule** (RFC 8446 §7.1): Early → Handshake → Master Secret; `KeySchedule` +
  `Transcript` (`IncrementalHash`); `HKDF-Expand-Label`. Handshake Traffic Secrets abgeleitet,
  Server-Handshake-Pakete von cloudflare-quic.com **live entschlüsselt**.
- ✅ Handshake-Nachrichten lesen: `HandshakeMessages` zerlegt den (reassemblierten) CRYPTO-Strom
  in EncryptedExtensions/Certificate/CertificateVerify/Finished.
- ✅ CertificateVerify: Signatur über den Transcript geprüft (ECDSA P-256/P-384, RSA-PSS) mit dem
  Leaf-Schlüssel — **immer**, als kryptografische Bindung ans Handshake; Kettenvalidierung via
  `X509Chain` + Hostname (`X509Certificate2.MatchesHostname`) gemäß `CertificateValidationOptions`
  (`Default` = volle Prüfung gegen System-Roots; `Insecure` = wie `curl -k`; `CustomTrustRoots` für
  Testzertifikate). Live gegen Cloudflare mit voller Kettenprüfung bestätigt (`CN=cloudflare-quic.com`).
- ✅ Finished-MAC (HMAC über Transcript): Server-Finished verifiziert **und** eigener (Client-)
  Finished berechnet und live gesendet (`KeySchedule.FinishedVerifyData`, `Finished.BuildMessage`).
- ✅ Client-Application (1-RTT) Secrets abgeleitet (`DeriveApplicationSecrets`); 1-RTT-Pakete des
  Servers (inkl. HANDSHAKE_DONE) live entschlüsselt.
- ✅ Client- und Server-Seite als expliziter Zustandsautomat (`TlsClientHandshake`/`TlsServerHandshake`
  hinter `ITlsHandshake`); Interface zum QUIC-Layer: „CRYPTO-Bytes auf Level X rein" / „CRYPTO-Bytes
  für Level Y raus" / „neue Schlüssel für Level Z verfügbar" (analog zum ngtcp2/quiche-Modell).
- ✅ **Prüfstein bestanden:** Key-Schedule-Testvektoren aus **RFC 8448** (TLS 1.3 Traces) werden
  byte-genau nachgerechnet (Early/Handshake Secret, c/s hs traffic, Traffic-Key-Ableitung).

### ✅ Phase 3 — QUIC-Verbindungsaufbau (RFC 9000 §5–§7, §12–§14)
Ziel: Vollständiger Handshake gegen einen echten Server (z. B. `cloudflare-quic.com`).
- ✅ Frames der ersten Stunde: `PADDING`, `PING`, `ACK`, `CRYPTO`, `CONNECTION_CLOSE` (+ STREAM,
  HANDSHAKE_DONE). Parsen/Serialisieren gegen RFC-9001-A.3-Payload verifiziert.
- ✅ Encryption Levels: Initial, Handshake, 1-RTT (+ 0-RTT) — Schlüssel + Pakete aller Levels.
  ✅ Coalesced Packets (mehrere QUIC-Pakete pro UDP-Datagramm) werden geparst.
- ✅ Verbindungs-Zustandsautomat: wiederverwendbare `QuicClientConnection` mit
  Encryption-Levels, Packet-Number-Spaces (`PacketNumberSpace`), CRYPTO-Reassemblierung und
  TLS-Engine (`TlsClientHandshake`, „CRYPTO rein / CRYPTO + Keys raus"-Modell) — treibt den
  Handshake bis HANDSHAKE_DONE; expliziter Zustand Closing/Draining/Closed, Idle-Timeout und
  Server-Seite (siehe Phase 8 / M3).
- ✅ ACK-Erzeugung: Ranges aus empfangenen Paketnummern (`AckFrame.FromPacketNumbers`), dauerhaft;
  ack_delay und ACK-Verarbeitung/Loss-Detection in Phase 5 umgesetzt.
- ✅ Transport-Parameter: Encode/Decode (`TransportParameters`) und Anwenden der ausgehandelten
  Limits (Flow Control, Stream-Limits, Idle-Timeout, active_connection_id_limit, …).
- ✅ **CRYPTO-Daten paketübergreifend**: Empfang (`CryptoStreamAssembler`, offset-basiert,
  ungeordnet/überlappend — Cloudflare-Zertifikatskette über 5 Handshake-Pakete reassembliert) **und
  Senden** (`AppendLevelPackets` verteilt ausgehende CRYPTO offset-korrekt auf mehrere Initial-/Handshake-
  Pakete, je ≤ MTU, `MaxCryptoDataPerPacket = 1000`). Der PQ-Hybrid-ClientHello (X25519MLKEM768,
  ~1450 Byte) geht so als **zwei** ≤1252-Byte-Initials raus (statt eines Übergroßdatagramms); Regressionstest
  über den Datagramm-Pfad + live gegen Cloudflare bestätigt (normal **und** `--mlkem`, je Status 200).
- ✅ UDP-Loop: Senden/Empfangen (Samples `H3Get`/`H3Server`) inkl. **Demultiplexing per Destination
  Connection ID** (migrationstauglich, siehe Phase 8); Single-Writer-/Channel-Architektur → Phase 9.
- ✅ Client-Initial auf ≥ 1200 Bytes padden (`InitialPacketFactory`); ✅ Anti-Amplification-Limit
  (3×) serverseitig (siehe Phase 8, in-process getestet).
- ✅ **Meilenstein M1 erreicht:** **Vollständiger** Handshake mit cloudflare-quic.com — ClientHello
  → ServerHello → Server-Flight entschlüsselt & Finished verifiziert → eigener Finished + ACKs
  gesendet → **HANDSHAKE_DONE** in einem 1-RTT-Paket empfangen. Handshake abgeschlossen, 1-RTT-Keys
  aktiv. ✅ Sauberes `CONNECTION_CLOSE`/Draining und Idle-Timeout inzwischen umgesetzt (Phase 8).
- ✅ ACK-Erzeugung aus empfangenen Paketnummern (`AckFrame.FromPacketNumbers`); NEW_TOKEN /
  NEW_CONNECTION_ID / RETIRE_CONNECTION_ID parsen (1-RTT-Flight).

### ✅ Phase 4 — Streams & Flow Control (RFC 9000 §2–§4, §19)
- ✅ `STREAM`-Frames (Offset/FIN/Length-Varianten), Reassemblierung out-of-order Daten
  (`StreamReceiveBuffer` mit Final-Size/Flow-Control-Prüfung; `StreamSendBuffer`).
- ✅ Bidirektionale + unidirektionale Streams, Stream-ID-Vergabe (`StreamId`, Bit-Kodierung).
  Server-Streams (HTTP/3-Control + QPACK) von cloudflare-quic.com live reassembliert.
- ✅ Flow Control: Frames `MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS`/`DATA_BLOCKED`/
  `STREAM_DATA_BLOCKED`/`STREAMS_BLOCKED`; Sende-Fensterbeachtung (Stream + Verbindung),
  Peer-Limits aus EncryptedExtensions dekodiert; empfangsseitiges MAX_*-Nachführen
  (`CollectFlowControlFrames`: ab halb verbrauchtem Fenster wird nachgewährt);
  dynamisches Window-Auto-Tuning → Phase 9.
- ✅ `RESET_STREAM` / `STOP_SENDING` **vollständig** (Senden/Empfangen/Retransmission,
  §3.5-Solicited-Reset, Final-Size-/Zustandsvalidierung — Details in Phase 8).
- ✅ Stream-API: `QuicStream` (`Write`/`Finish`/`Read`/`Reset`/`AbortRead`);
  async/Backpressure-API → Phase 9.
- ✅ 1-RTT-Sendepfad (`ShortHeader.Build`) — App-Pakete mit ACK + STREAM-Frames.

### ✅ Phase 5 — Loss Detection & Congestion Control (RFC 9002)
Ohne diese Phase funktioniert alles nur im Labor; mit Paketverlust bricht sonst der Handshake ab.
- ✅ RTT-Schätzung (`RttEstimator`: smoothed_rtt, rttvar, min_rtt; ack_delay berücksichtigt).
- ✅ Loss Detection (`LossRecovery`): Packet-Threshold (3) + Time-Threshold; Probe Timeout (PTO)
  mit Backoff.
- ✅ Retransmission: verlorene **Frames** (CRYPTO/STREAM) werden neu eingereiht und umgepackt.
- ✅ Congestion Control: **NewReno** (`NewRenoCongestionControl`: Slow Start, Congestion Avoidance,
  Recovery).
- ✅ **cwnd-Enforcement + Pacing im Sendepfad** (RFC 9002 §7/§7.7): neue Stream-Daten werden pro
  `GetDatagramsToSend` durch `min(cwnd − bytes_in_flight, Pacing-Budget)` begrenzt; der `Pacer`
  (Token-Bucket, Rate `1.25·cwnd/smoothed_rtt`, Burst-Cap ≈ Initial Window) verteilt sie zeitlich.
  Reine ACKs und PTO-Probes sind ausgenommen. Der 1-RTT-Sendepfad emittiert nun mehrere **MTU-große**
  Pakete pro Aufruf statt eines überdimensionierten.
- ✅ **Persistent Congestion** (RFC 9002 §7.6): kollabiert das Fenster auf `kMinimumWindow`, wenn zwei
  ack-eliciting Pakete verloren sind, dazwischen nichts bestätigt wurde und ihr Sende-Abstand die
  PC-Dauer `(srtt + max(4·rttvar, granularity) + max_ack_delay)·3` übersteigt (nur nach der ersten
  RTT-Stichprobe). Konservative Näherung über konsekutive Paketnummern (keine falsch-positiven).
- ✅ **Idle Timeout** (RFC 9000 §10.1): `IdleTimeout` handelt `min(lokal, peer)` aus (0 = deaktiviert),
  hebt auf mind. `3·PTO` an, startet den Timer bei erfolgreichem Empfang und beim Senden eines
  ack-eliciting Pakets (nur einmal je Empfang) neu. `QuicEndpoint.CheckIdleTimeout()` schließt die
  Verbindung still (keine Datagramme mehr). H3Server reapt inaktive Verbindungen (`--idle=<ms>`).
- ✅ **Keep-Alive via PING** (RFC 9000 §10.1.2): `KeepAliveInterval` gesetzt ⇒ nach so viel Inaktivität
  wird ein PING (ack-eliciting) eingeplant, das den Idle-Timeout beidseitig zurücksetzt.
  `IdleTimeout.ShouldSendKeepAlive` steuert die Kadenz; live gezeigt mit `H3Get --hold=<s>` gegen einen
  Server mit kurzem `--idle` (Verbindung überlebt, wo sie sonst gereapt würde).
- ✅ **Prüfstein bestanden:** Sample `H3Get --loss=N` verwirft einen Bruchteil der Datagramme;
  Handshake + 126-KB-GET überstehen 10 % Verlust (≈17 Datagramme verworfen, via Retransmission
  überbrückt). RTT/NewReno/LossRecovery/**Pacer**/**Persistent Congestion** per Unit-Tests abgesichert;
  ein 150-KB-In-Process-Transfer beweist, dass der gepacte, cwnd-begrenzte Sendepfad byte-genau und
  MTU-konform überträgt.

### ✅ Phase 6 — QPACK (RFC 9204), minimal aber korrekt
- ✅ **Stufe 1 (reicht für volle Interop):** Encoder/Decoder ohne dynamische Tabelle —
  statische Tabelle (99 Einträge, `QpackStaticTable`) + Literale, Huffman (`Huffman`, Tabelle aus
  RFC 7541 App. B, per Skript generiert), N-Bit-Integer und String-Codec (`QpackPrimitives`).
  Verifiziert: RFC-9204-B.1-Beispiel (Decode), RFC-7541-Huffman-Vektoren, Round-Trips typischer
  Request-Header. `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` wird angesagt → Peer bleibt auch statisch;
  Verweise auf die dynamische Tabelle werden abgelehnt (`QpackResult.DynamicTableReference`).
- ✅ Encoder-/Decoder-Streams (Pflicht in HTTP/3): beidseitig geöffnet und verdrahtet (Stufe 2 unten +
  Phase 7); bei Kapazität 0 bleiben sie praktisch leer.
- ✅ **Stufe 2 (dynamische Tabelle):** `QpackDynamicTable` (FIFO, Byte-Kapazität, Eviction, absolute
  Indizierung), `QpackDynamicEncoder` (erzeugt Insert-Instruktionen + Field Section, Base = RIC → pre-base),
  `QpackDynamicDecoder` (Encoder-Stream: Set Capacity / Insert Name-Ref static+dynamic / Insert Literal /
  Duplicate; Field Section: indexed static/dynamic, Post-Base, literale Namen; RIC-Modulo-Rekonstruktion
  §4.5.1). **Byte-genau gegen RFC-9204-Anhang-B.2 verifiziert** (Decode), plus Round-Trip/Reuse/Eviction.
  **In den Live-HTTP/3-Pfad verdrahtet** (`Http3Qpack`): SETTINGS kündigen die Kapazität an, die Uni-Streams
  des Peers (Control + QPACK-Encoder) werden gelesen, Instruktionen streamend verarbeitet, blockierte
  HEADERS werden gepuffert und erneut versucht (Blocked-Streams-Handling). Gated: Kapazität 0 = rein
  statisch (Cloudflare bleibt so); `--qpack-dynamic` aktiviert sie gegen den eigenen Server. **Live über UDP
  bestätigt** (Request-/Antwort-Inserts fließen beidseitig, Status 200).
- ✅ **Decoder-Stream-Feedback** (RFC 9204 §4.4): Der Decoder sendet nach einer dynamischen Sektion eine
  **Section-Acknowledgment** (auf dem QPACK-Decoder-Stream); der Encoder verarbeitet Section-Ack /
  Stream-Cancellation / Insert-Count-Increment und gibt daraufhin die **Referenzen** frei. Die Tabelle zählt
  Referenzen und verdrängt keinen noch referenzierten Eintrag (Eviction-Schutz, §2.1.1) – ohne Acks stapeln
  sich Referenzen und Inserts fallen auf Literale zurück; mit Acks bleibt die Tabelle nutzbar. In-process
  getestet (Ack gibt Referenz frei → Eviction wieder möglich) und live (Server erhält die Client-Acks).

### ✅ Phase 7 — HTTP/3 (RFC 9114) — Feature-Audit komplett
Bewusst offen bleiben nur noch: Server-Push (MAY), klassisches CONNECT-Proxying.
- ✅ **WebTransport über HTTP/3** (draft-ietf-webtrans-http3-13) — der komplette Draft inkl. Flow Control:
  - **Session-Aufbau** (§3): Extended CONNECT mit `:protocol = webtransport`; Gating über
    SETTINGS_WT_MAX_SESSIONS (0x14e9cd29) + ENABLE_CONNECT_PROTOCOL + H3-/QUIC-Datagramme (§3.1); ohne
    Datagramme ⇒ malformed; unbekannte Ressource ⇒ 404; über WT_MAX_SESSIONS ⇒ H3_REQUEST_REJECTED (§5.2).
    `Http3ClientConnection.ConnectWebTransport`/`TryGetWebTransportSession`, Server `webTransportHandler`.
  - **Streams** (§4.1/§4.2): unidirektional (Typ 0x54 ‖ Session-ID), bidirektional (WT_STREAM 0x41 ‖
    Session-ID); beide Seiten öffnen/empfangen; Routing über `WebTransportManager` (client- und
    server-initiiert), früh eingetroffene Streams gepuffert (§4.5, Überlauf ⇒ WT_BUFFERED_STREAM_REJECTED).
    Reset/StopSending bilden 32-Bit-App-Codes byte-genau in den WT_APPLICATION_ERROR-Bereich ab (§4.3);
    richtungsabhängig (send-only-Uni ⇒ nur RESET, receive-only-Uni ⇒ nur STOP_SENDING).
  - **Datagramme** (§4.4): über die HTTP-Datagram-Infra (Quarter Stream ID = CONNECT-Stream).
  - **Flow Control** (§5): Capsule-Protokoll (RFC 9297 §3.2) auf dem CONNECT-Stream; WT_MAX_STREAMS
    (0x190B4D3F/40), WT_MAX_DATA (0x190B4D3D), WT_STREAMS_BLOCKED/WT_DATA_BLOCKED — Limits aus
    SETTINGS_WT_INITIAL_MAX_* + proaktives Nachführen; aktiv nur bei WT_MAX_SESSIONS > 1 (§5.1).
  - **Session-Ende** (§6): WT_CLOSE_SESSION-Capsule (0x2843, 32-Bit-Code + UTF-8-Grund) + FIN; sauberes
    FIN = Code 0; alle zugehörigen Streams mit WT_SESSION_GONE abgebrochen.
  - **Protokoll-Aushandlung** (§3.3, ALPN-artig): Client bietet per `WT-Available-Protocols`
    (Structured-Fields-List aus Strings, RFC 9651, Präferenz zuerst) an; der Server wählt per
    `WT-Protocol` (SF-Item-String) in der 2xx-Antwort GENAU eines davon. Nicht-String-Werte machen
    das GESAMTE Feld ungültig, Parameter werden ignoriert, eine Wahl außerhalb der Angebotsliste wird
    beidseitig verworfen (alle §3.3-MUSTs). API: `ConnectWebTransport(…, availableProtocols:)`,
    Server-ctor `webTransportProtocolSelector`, `WebTransportSession.NegotiatedProtocol`;
    SF-Kodierung in `WebTransportProtocols` (eigener strikter RFC-9651-Parser für List/Item/String
    inkl. Parameter-Überlesen aller Bare-Item-Typen).
  - **Keying-Material-Exporter** (§4.7): TLS-Exporter (RFC 8446 §7.5) über das neu abgeleitete
    `exporter_master_secret` (§7.1, gegen RFC 8448 verifiziert) — Kette KeySchedule →
    ITlsHandshake/beide Handshakes → `QuicEndpoint.ExportKeyingMaterial` →
    `WebTransportSession.ExportKeyingMaterial` (Label fest `EXPORTER-WebTransport`, Kontext =
    Session-ID(64) ‖ App-Label(1–255) ‖ App-Kontext(0–255) ⇒ getrenntes Material je Session,
    identisches je Session-Ende).
  - 7 Tests (Error-Mapping, Capsule-Reader, Support-Gating, Session/404, Datagramm+uni+bidi-Echo
    end-to-end, Close mit Code/Grund, Session-Limit) + 7 Tests Protokoll-Aushandlung (SF-Kodierung/
    -Ablehnung, Ende-zu-Ende-Wahl, Out-of-List-Guard, ohne Angebot) + 5 Tests Exporter (RFC-8448-
    Vektor, Determinismus/Label-Kontext-Trennung, QUIC-Ende-zu-Ende, vor Handshake, WT-Sessions).
    **Live über UDP:** `H3Get --webtransport` gegen `H3Server` — Session, Datagramm-Echo,
    uni-/bidi-Stream (Echo), sauberes Ende, WT-Protocol `echo-v2` aus `echo-v3, echo-v2, echo-v1`
    ausgehandelt, Keying-Material-Export in beiden Prozessen byte-identisch; alle anderen
    Sample-Modi + Cloudflare regressionsfrei. **Damit ist draft-webtrans-http3-13 KOMPLETT.**
- ✅ **RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-08)** — Stream-Reset mit garantierter
  Teilzustellung (die Grundlage dafür, dass der WebTransport-Stream-Präfix trotz Reset ankommt):
  - **Transport-Parameter** `reset_stream_at` (0x1d, leerer Wert): kündigt Empfangsbereitschaft an
    (Standard aktiv); nicht-leerer Wert ⇒ TRANSPORT_PARAMETER_ERROR. `PeerSupportsResetStreamAt`
    steuert, ob wir dem Peer AT-Frames senden dürfen.
  - **Frame** RESET_STREAM_AT (Typ 0x24): wie RESET_STREAM plus Reliable Size. Reliable Size > Final
    Size ⇒ FRAME_ENCODING_ERROR.
  - **Empfangsseite:** liefert die ersten Reliable-Size-Bytes weiter an die Anwendung (Lese-Offset
    entkoppelt von der Flow-Control-Abrechnung, die die volle Final Size verbucht); spätere Frames
    dürfen die Reliable Size nur senken (§5.2, Erhöhungen aus Reordering werden ignoriert), ein
    geänderter Fehlercode ⇒ STREAM_STATE_ERROR.
  - **Sendeseite:** `QuicStream.ResetAt(code, reliableSize)` garantiert bereits gesendete Bytes
    (Reliable Size auf den Sende-Offset begrenzt); STREAM-Frames unterhalb der Reliable Size werden
    bei Verlust weiter retransmittiert; ohne Peer-Unterstützung degradiert der Abbruch zu RESET_STREAM.
  - 13 Tests (Frame-Roundtrip/Truncation, TP-Kodierung/Ablehnung, Empfangs-Teilzustellung/Senkung/
    Fehlercode-Wechsel/Spät-Frame-Kappung, Sende-Emission/Degradierung/Clamping, Ende-zu-Ende über
    echte QUIC-Frames). **Live über UDP:** Cloudflare akzeptiert den TP 0x1d (Handshake + GET 200).
- ✅ **HTTP-Datagramme (RFC 9297) über QUIC-DATAGRAM (RFC 9221)** — die Grundlage von MASQUE/WebTransport:
  - **QUIC-Schicht (RFC 9221):** Transport-Parameter `max_datagram_frame_size` (0x20, senden/parsen),
    `DatagramFrame` (Typ 0x30 ohne / 0x31 mit Length), Emission im 1-RTT-Sendepfad (unfragmentierbar
    ⇒ ein Frame pro Paket, congestion-controlled, NICHT retransmittiert), Empfang mit
    PROTOCOL_VIOLATION bei fehlender Ankündigung bzw. Übergröße (§3). API: `TrySendDatagram`
    (verweigert ohne Peer-TP / über MTU) + `TakeReceivedDatagrams`.
  - **HTTP/3-Schicht (RFC 9297):** Setting `SETTINGS_H3_DATAGRAM` (0x33, Wert 0/1 sonst H3_SETTINGS_
    ERROR), beidseitige Aushandlung (`DatagramsNegotiated` = Setting gesendet+empfangen UND
    max_datagram_frame_size > 0). HTTP/3-Datagram-Format = Quarter Stream ID (Stream-ID / 4) + Payload;
    Zuordnung zum Request-Stream/Tunnel. Fehler: unparsbare/zu große Quarter Stream ID ⇒
    H3_DATAGRAM_ERROR (0x33, Verbindungsfehler); Datagramm zu einem Request ohne Datagram-Semantik
    (z. B. GET) ⇒ Request abbrechen mit H3_DATAGRAM_ERROR (Stream-Fehler); unbekannter Stream ⇒ still
    verwerfen. `Http3Tunnel.TrySendDatagram/TryReceiveDatagram` (unzuverlässig: Überlauf verwirft ältestes).
  - 7 Tests (Frame-Round-Trip beide Varianten, keine Aushandlung ⇒ kein Senden, **Echo end-to-end über
    Tunnel**, GET+Datagramm ⇒ Stream-Reset, malformed ⇒ Verbindungsfehler, unbekannter Stream verworfen,
    ungültiger Setting-Wert). **Live über UDP:** `H3Get --datagrams` gegen `H3Server` (Route
    `datagram-echo`) — Aushandlung, CONNECT 200, 3/3 Datagramme in DATAGRAM-Frames geecht;
    Cloudflare-GET regressionsfrei.
- ✅ **WebSockets über HTTP/3 (RFC 9220 / RFC 8441 / RFC 6455)**:
  - **RFC-6455-Framing wiederverwendet:** die WebSocket-Dateien aus Hermod (`Hermod.HTTP2.WebSocket*`
    + `IHTTP2Tunnel`) sind als **byte-identische Kopien** (einzige Änderung: Namespace-Zeile →
    `…Hermod.HTTP3`) unter `src/Http3/WebSocket/` übernommen — das Framing ist transport-agnostisch
    gegen das 2-Methoden-Tunnel-Interface geschrieben; Dedup-Plan im dortigen README.
  - **Extended CONNECT (RFC 8441)**: SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08, Wert MUSS 0/1 sein sonst
    H3_SETTINGS_ERROR); `:protocol`-Pseudo-Header im Validator (nur auf CONNECT; mit :protocol MÜSSEN
    :scheme/:path da sein, :authority nach normalen Regeln; klassischer CONNECT unverändert). Client
    `SendExtendedConnect` (wirft ohne Server-Setting, §3 MUST NOT) + `TryGetConnectResponse`; Server
    `connectHandler` (kündigt das Setting an; unbekanntes :protocol ⇒ **501**, RFC 9220 §3; Extended
    CONNECT ohne Setting ⇒ malformed/400).
  - **Tunnel-Modus** (`Http3Tunnel : IHTTP2Tunnel`): CONNECT wird SOFORT bei den HEADERS behandelt
    (kein FIN-Warten); nach 2xx reisen die Tunnel-Bytes in DATA-Frames (RFC 9114 §4.4 — andere
    bekannte Frames ⇒ H3_FRAME_UNEXPECTED); FIN ≙ geordnetes TCP-Close, Reset ≙ RST mit
    H3_REQUEST_CANCELLED (RFC 9220 §3). Async-Brücke single-threaded: ausstehende `ReadAsync` werden
    inline im Pump vollendet (race-frei ohne Locks).
  - 7 Tests (Setting-Gate beidseitig, 501, **Text-/Binär-Echo + Close-Handshake end-to-end**,
    permessage-deflate ausgehandelt + Round-Trip, DATA-only-MUST, :protocol-Validator).
    **Live über UDP:** `H3Get --websocket` — Setting → CONNECT 200 → RFC-6455-Text-Echo →
    Close-Handshake → geordnetes Tunnel-Ende; Cloudflare-GET regressionsfrei.
- ✅ **Priorities (RFC 9218)** — die einzige „wichtige" Extension, jetzt umgesetzt:
  - **Signale**: `priority`-Header (Structured-Fields-Dictionary, fehlertolerant geparst:
    unbekannte/typfremde/außer-Bereich-Parameter werden ignoriert — MUST; `u` 0–7 Default 3,
    `i` Boolean Default false; `Http3Priority.Parse/ToHeaderValue`) und **PRIORITY_UPDATE**-Frame
    (0xF0700, Payload = Element-ID-VarInt + ASCII-Field-Value) — `Http3Request.Priority` und
    `Http3ClientConnection.SendPriorityUpdate(streamId, priority)`.
  - **MUSTs (§7.2)**: PRIORITY_UPDATE nur auf dem Client-Control-Stream (sonst H3_FRAME_UNEXPECTED,
    auch beim Client als Empfänger — Server senden NIE); Nicht-Request-Stream-ID ⇒ H3_ID_ERROR;
    Push-Variante 0xF0701 ⇒ H3_ID_ERROR (nie versprochen); Layout ⇒ H3_FRAME_ERROR. Updates für noch
    nicht geöffnete Streams werden gepuffert (letztes gewinnt, begrenzt auf 32) und beim Öffnen
    angewandt; ein Update **überschreibt** den Header (§7).
  - **Server-Scheduling (§10)**: `QuicStream.SendUrgency/SendIncremental` + priorisierte Stream-Wahl
    im QUIC-Sendepfad (`PickSendStream`): aufsteigende Urgency; gleiche Urgency nicht-inkrementell ⇒
    exklusiv in aufsteigender Stream-ID (Request-Reihenfolge), inkrementell ⇒ Round-Robin
    (Bandbreite teilen). Control-/QPACK-Streams laufen mit Urgency 0 (nie verhungern).
  - 10 Tests (Parser, Urgency-Ordnung, FIFO, inkrementelles Teilen, Header-Override, Buffering vor
    Stream-Öffnung, 4 Zustandsmaschinen-MUSTs). **Live über UDP**: `H3Get --priorities` gegen
    `H3Server` (Route `/big`) — der u=0-Download überholt den früher angefragten Default-Download,
    und ein PRIORITY_UPDATE (u=7) stuft einen u=0-„Prefetch" nachträglich hinter u=3 zurück.
    Cloudflare-GET regressionsfrei.
- ✅ Unidirektionale Streams mit Typ-Präfix: Control (0x00), QPACK Encoder (0x02) /
  Decoder (0x03); Control-Stream geöffnet, `SETTINGS` als erstes Frame.
- ✅ Frames: `DATA`, `HEADERS`, `SETTINGS` (inkrementelles Parsen, unbekannte Frames ignoriert –
  Greasing). `MAX_PUSH_ID`/`CANCEL_PUSH` bewusst nur validierend (kein Push).
- ✅ **MAX_FIELD_SECTION_SIZE** (RFC 9114 §4.2.2): Größenformel Σ(Name + Wert + 32) je Feld,
  unkomprimiert (`Http3Qpack.FieldSectionSize`). Beide Seiten können ein Limit ankündigen
  (`maxFieldSectionSize`-Parameter ⇒ SETTINGS 0x06) und parsen das des Peers. **Sender (SHOULD NOT):**
  Client wirft bei zu großen Request-Headern/-Trailern (`ArgumentException`); Server stuft zu große
  Antwort-Header auf ein minimales **500** herab, lässt zu große Interim-/Trailer-Sektionen weg.
  **Empfänger (MAY):** Server beantwortet zu große Request-Header mit **431** (RFC 6585) ohne
  Handler-Aufruf + STOP_SENDING H3_NO_ERROR (§4.1); Client verwirft zu große Antworten
  (`IsResponseTooLarge`, Stream-Abbruch, Verbindung lebt). 5 Tests (Formel, Client-Verweigerung,
  431 via Roh-Client, 500-Herabstufung, Client-Verwerfen via Roh-Server). **Live:** Cloudflare kündigt
  **131072** an (geparst, respektiert); eigener H3Server kündigt 16384 an — GET je Status 200.
- ✅ **Trailer-Sektionen + Interim-Responses (1xx)** (RFC 9114 §4.1): `Http3Request.Trailers`/
  `Http3Response.Trailers` werden als abschließendes HEADERS-Frame nach dem Content gesendet und beim
  Empfang getrennt von der Header-Sektion abgelegt (beide Richtungen). `Http3Response.InterimResponses`
  (z. B. **103 Early Hints**): der Server sendet je Interim eine eigene 1xx-HEADERS-Sektion VOR der
  finalen Antwort; der Client trennt sie anhand von `:status` (100–199) sauber ab — die finale
  Header-Sektion bleibt rein. Verstoß „Content nach Interim" (Interims tragen keinen Content) ⇒
  **malformed** ⇒ STREAM-Fehler `H3_MESSAGE_ERROR` (§4.1.2, `IsResponseMalformed`; Verbindung lebt
  weiter). 5 Tests (Trailer beidseitig, Trailer ohne Content, 2× 103 + finale Antwort, Malformed via
  Roh-Server). **Live über UDP:** `H3Get localhost /hints` — „HTTP/3 103 (Interim) — link: …preload…" →
  200 → „Trailer: checksum: …"; Cloudflare-GET regressionsfrei.
- ✅ **GOAWAY / Graceful Shutdown** (RFC 9114 §5.2): Server `InitiateGracefulShutdown()` sendet GOAWAY
  mit der ersten NICHT mehr angenommenen Request-Stream-ID (`GoAwaySent`), bedient Laufendes zu Ende
  (`HasPendingRequests`), weist spätere Request-Streams mit RESET_STREAM/STOP_SENDING
  `H3_REQUEST_REJECTED` zurück (kein Handler-Aufruf, kein Verbindungsfehler) und schließt danach per
  `CloseGracefully()` mit **H3_NO_ERROR** (Typ 0x1d). Client: `GoAwayStreamId`, `SendRequest` wirft
  nach GOAWAY (MUST NOT), In-Flight-Requests ≥ der Grenze werden als `IsRequestRejected` markiert
  (gefahrlos wiederholbar) und transportseitig aufgeräumt; anwachsende GOAWAY-IDs ⇒ H3_ID_ERROR.
  4 Tests (End-to-End, später Request via Roh-Client, In-Flight-Rejection, ID-Anwachsen);
  **live über UDP:** `H3Server --goaway` + `H3Get --goaway` — GET 200 → GOAWAY (Grenze 4) → neuer
  Request korrekt verweigert → CONNECTION_CLOSE 0x100 (H3_NO_ERROR).
- ✅ Request/Response: Pseudo-Header (`:method`/`:scheme`/`:authority`/`:path`/`:status`),
  Mapping Request ↔ bidirektionaler Stream.
- ✅ **Malformed-Erkennung** (RFC 9114 §4.1.2/§4.2/§4.3, `Http3MessageValidator` — bewusst strikt):
  Pseudo-Header-Pflichten (genau ein `:method`/`:scheme`/`:path`; `:authority` ODER `Host`, nicht leer,
  konsistent, ohne userinfo; genau ein numerischer `:status` 100–599), undefinierte/kontextfremde
  Pseudo-Header, Pseudo-Header nach regulären Feldern oder in Trailern, Großbuchstaben/ungültige
  Zeichen in Feldnamen, NUL/CR/LF in Werten (Smuggling-Schutz), verbindungsspezifische Felder
  (`connection`/`keep-alive`/`transfer-encoding`/`upgrade`/…; `te` nur „trailers"), Content-Length-
  Konsistenz (= Σ DATA-Längen; Ausnahme rumpflose Antworten: HEAD/204/304). **Reaktion:** Server
  ⇒ **400** (MAY) + Leseabbruch mit Stream-Fehler `H3_MESSAGE_ERROR`, kein Handler-Aufruf; Client
  ⇒ Antwort verwerfen (MUST NOT accept, `IsResponseMalformed`); eigene malformed Requests wirft
  `SendRequest` lokal (`ArgumentException`, MUST NOT generate). Gültiger **CONNECT** (§4.4) wird
  erkannt und mit **501** beantwortet (nicht unterstützt). 15 Tests (Validator-Units + Wire-Level
  mit Roh-Peers; Großbuchstaben via Literal-Literal-QPACK nachgestellt, da unsere Encoder Namen
  konventionsgemäß kleinschreiben). **Live:** Cloudflare-GET (deren `content-length` besteht die
  Konsistenzprüfung real), lokal `/hints` + POST-Echo — je Status 200.
- ✅ **Request-Bodies** (RFC 9114 §4.1): `Http3Request.Body`/`Post(...)` — der Client sendet den Rumpf
  als DATA-Frame nach dem HEADERS-Frame (mit automatischem `content-length`, §4.1.2: Wert = Summe der
  DATA-Längen); der Server sammelt DATA-Frames ein und antwortet erst bei vollständiger Nachricht (FIN).
  Eine Trailer-Sektion (zweites HEADERS) wird QPACK-korrekt dekodiert (Section-Acks), inhaltlich noch
  verworfen. Tests: POST-Echo (Header + Rumpf byte-genau) und **120-KB-Upload** — treibt erstmals den
  Client-Sendepfad (cwnd/Pacing/MTU) unter Last, SHA-256-verifiziert. **Live:** POST `/echo` gegen den
  eigenen H3Server über UDP (Echo byte-genau) und POST gegen cloudflare-quic.com (Status 200) —
  `H3Get --post=<Text>`.
- ✅ Fehlerbehandlung: H3-Fehlercodes (RFC 9114 §8.1) als `Http3Error`-Konstanten; **Request-
  Cancellation** (§4.1.1): `CancelRequest` setzt die Sendeseite zurück und bricht das Lesen ab (beides
  H3_REQUEST_CANCELLED); der Server erkennt Client-Abbrüche (RESET_STREAM ⇒ eigene Antwortseite
  H3_REQUEST_REJECTED/CANCELLED zurücksetzen, STOP_SENDING ⇒ automatischer Reset via RFC 9000 §3.5);
  `IsRequestCancelled`/`RequestResetErrorCode`; eine bereits vollständige Antwort bleibt nutzbar.
  **Live:** `H3Get --cancel` gegen cloudflare-quic.com — Abbruch mitten im Download, Cloudflare
  resettet mit 0x10c (kopierter Code), zweites GET über dieselbe Verbindung Status 200.
- ✅ **Frame-/Stream-Zustandsmaschine** (§4.1, §6.2, §7.2) — Verstöße ⇒ CONNECTION_CLOSE **Typ 0x1d**
  (`CloseApplication` im QUIC-Layer) mit H3-Fehlercode:
  - Control-Stream: erstes Frame MUSS SETTINGS sein (H3_MISSING_SETTINGS), zweites SETTINGS/DATA/
    HEADERS/PUSH_PROMISE ⇒ H3_FRAME_UNEXPECTED; zweiter Control-/QPACK-Stream ⇒ H3_STREAM_CREATION_
    ERROR; Schließen/Reset kritischer Streams ⇒ H3_CLOSED_CRITICAL_STREAM (§6.2.1, RFC 9204 §4.2).
  - Request-Streams: DATA vor HEADERS / Frames nach der Trailer-Sektion, SETTINGS/GOAWAY/MAX_PUSH_ID/
    CANCEL_PUSH ⇒ H3_FRAME_UNEXPECTED; PUSH_PROMISE: vom Client ⇒ H3_FRAME_UNEXPECTED (Server), ohne
    MAX_PUSH_ID ⇒ H3_ID_ERROR (Client); Push-Stream: client-initiiert ⇒ H3_STREAM_CREATION_ERROR,
    ohne MAX_PUSH_ID ⇒ H3_ID_ERROR.
  - Reservierte HTTP/2-Frame-Typen (0x02/0x06/0x08/0x09) ⇒ H3_FRAME_UNEXPECTED (§7.2.8); reservierte/
    doppelte SETTINGS-IDs ⇒ H3_SETTINGS_ERROR; Layout-Fehler (GOAWAY/CANCEL_PUSH/MAX_PUSH_ID ≠ genau
    ein VarInt, SETTINGS-Reste, abgeschnittenes letztes Frame bei FIN) ⇒ H3_FRAME_ERROR (§7.1).
  - GOAWAY mit Nicht-Request-Stream-ID beim Client ⇒ H3_ID_ERROR (§7.2.6; `GoAwayId` gemerkt — Semantik
    folgt mit dem GOAWAY-Schritt). Grease-Frames/-Settings (0x1f·N+0x21) werden ignoriert; eigene
    SETTINGS enthalten jetzt ein Grease-Setting (§7.2.4.1 SHOULD). 14 Tests mit „bösem" Roh-QUIC-Peer
    in beide Richtungen; **live:** GET + 0-RTT gegen Cloudflare und eigener Server (dyn. QPACK) laufen
    unverändert — die strengere Validierung bricht keine Interop.
- ✅ Öffentliche API: `Http3ClientConnection` (`InitializeHttp3`/`SendRequest`/`TryGetResponse`/
  `CancelRequest`, transport-agnostisch) **und** `Http3ServerConnection` (Handler-Modell,
  `InitiateGracefulShutdown`); ergonomischer `Http3Client.GetAsync(uri)`-Wrapper → Phase 9.
- ✅ Server-Push weggelassen (MAY; PUSH-bezogene Frames/Streams werden validierend abgewiesen).
- ✅ **Meilenstein M2 erreicht:** `GET https://cloudflare-quic.com/` liefert Status 200 + 126 KB
  HTML über den eigenen Stack (QPACK-dekodierte Header, Rumpf reassembliert).
- ✅ **Client-Interop-Matrix — 8 unabhängige QUIC-Implementierungen** (alle live über UDP, mit
  **voller** Zertifikatskette + Hostname-Prüfung, ohne `-k`; Stand 2026-07-23):

  | Ziel | Fremd-Stack | KEX / Suite / Cert | Ergebnis |
  |---|---|---|---|
  | cloudflare-quic.com / cloudflare.com | **quiche** (Cloudflare) | X25519 / AES-128-SHA256 / ECDSA | 200 / 301 |
  | quic.nginx.org | **nginx QUIC** | X25519 / AES-128-SHA256 / ECDSA P-256 | 200 |
  | www.google.com | **Google QUIC** | X25519 / AES-128-SHA256 | 200 |
  | www.facebook.com | **mvfst** (Meta) | X25519 / AES-128-SHA256 | 302 |
  | www.litespeedtech.com | **lsquic** (LiteSpeed) | X25519 / AES-128-SHA256 | 200 |
  | outlook.office.com | **msquic** (Microsoft) | **P-256 / AES-256-SHA384 / RSA** | 301 |
  | caddyserver.com / http3.is | **quic-go** (Go, via Caddy) | X25519 / AES-128 & AES-256 / ECDSA & RSA | 200 |
  | www.akamai.com | **Akamai QUIC** | X25519 / **AES-256-SHA384** / ECDSA | 403* |

  *403/301/302 sind reguläre HTTP-Antworten (Bot-Schutz/Redirect) — der HTTP/3-Stack läuft in allen
  Fällen end-to-end durch. Die Matrix deckt beide KEX (X25519 **und** P-256), beide Suiten
  (AES-128-GCM-SHA256 **und** AES-256-GCM-SHA384) und beide Zertifikatstypen (ECDSA **und** RSA-PSS)
  ab — outlook.office.com übt als einziges den kompletten P-256 + AES-256 + RSA-Pfad live. (Hinweis:
  `www.microsoft.com` bietet gar kein HTTP/3 — mit `curl --http3-only` gegengeprüft.) **Jederzeit
  wiederholbar** per `dotnet run --project samples/H3Get -- --interop`; gepflegt in
  [INTEROP.md](INTEROP.md) (dort auch der Server-Seiten-`curl`-Nachweis).
- ✅ **Meilenstein M3 erreicht (über eigenen Client):** Server-Seite gebaut — `TlsServerHandshake`
  (ServerHello/EE/Certificate/CertificateVerify-Signatur/Finished, Client-Finished-Prüfung),
  `ServerCertificate` (self-signed ECDSA P-256 via `CertificateRequest`), `QuicServerConnection`,
  `Http3ServerConnection`. Sample `H3Server` (UDP): unser `H3Get`-Client holt darüber Status 200 +
  HTML über echtes localhost-UDP; zusätzlich In-Process-Test (Client↔Server, beide from scratch).
  ✅ Interop-Bausteine: **X25519** (BouncyCastle, `IKeyExchange`) und **HelloRetryRequest** (Client +
  Server) implementiert. Client bietet X25519+P-256 an; Server wählt aus den Key Shares bzw. sendet HRR.
  Live-Beweis: gegen cloudflare-quic.com wird X25519 ausgehandelt.
- ✅ **`curl --http3`-Interop (Server-Seite)** — gegen ZWEI unabhängige fremde HTTP/3-Stacks:
  - **Windows:** offizielles curl-8.21.0-Paket (curl.se, **ngtcp2 1.24 + nghttp3 1.17 + LibreSSL 4.3.2**)
    → `curl --http3-only -k https://127.0.0.1:4433/` gegen `H3Server`: Handshake, GET 200 (HTML),
    POST /echo (Rumpf byte-genau zurück), GET /big (300 000 B in ~22 ms), GET /hints (**103 Early
    Hints + finale 200 + Trailer `checksum` werden von curl angezeigt**), Connection-Reuse.
  - **WSL (Debian 13):** Distro-curl 8.14.1 mit **OpenSSL-3.5-QUIC** (curls openssl-quic-Backend,
    kein ngtcp2!) + nghttp3 → dieselben Tests über die WSL2-NAT-Grenze (Host-IP aus `ip route`):
    GET 200, POST-Echo, 300 000 B in ~38 ms, 103+Trailer; saubere Closes (Fehlercode 0).
  - Damit ist die Server-Seite gegen ngtcp2/LibreSSL, OpenSSL-QUIC UND (Client-Seite) Cloudflares
    quiche interop-bestätigt. (Das lokale System-curl ist ein Schannel-Build ohne HTTP/3 — das
    HTTP/3-fähige curl liegt als entpacktes Paket im Session-Scratchpad; in WSL ist es vorinstalliert.)

### 🔶 Phase 8 — Robustheit & Server-Vollständigkeit
- ✅ **Version Negotiation** (RFC 9000 §6): Server sendet ein VN-Paket bei nicht unterstützter Version
  (`VersionNegotiationPacket`, DCID/SCID vertauscht, unterstützte Versionen gelistet). **Anti-Amplification
  (§6.1/§14.1):** kein VN auf Datagramme < 1200 B. **GREASE (§6.3):** eine reservierte Version im Muster
  `0x?a?a?a?a` wird beigelegt (prüft Client-Robustheit, beugt Ossifizierung vor). Client erkennt VN
  (Versionsfeld 0), verwirft es nach §6.2-Regeln (bereits Paket verarbeitet / eigene Version gelistet),
  ignoriert die reservierte Version und gibt sonst auf (`VersionNegotiationReceived`/`OfferedVersions`).
  In-process getestet (Empfang, GREASE-Version, kein VN auf zu kleines Datagramm).
- ✅ **Retry / Adressvalidierung** (RFC 9000 §8.1, §17.2.5; RFC 9001 §5.8): Server optional hinter
  `requireRetry`/`--retry` — sendet auf das erste tokenlose Initial ein `RetryPacket` (Integrity Tag über
  die ODCID), validiert das zurückgespiegelte Token. Client prüft den Tag, leitet die Initial-Schlüssel
  aus der Retry-SCID neu ab (RFC 9001 §5.2), sendet den ClientHello mit Token erneut. `retry_source_
  connection_id`-TP ergänzt. **Live über UDP bestätigt** (H3Get „nach Retry"). Nebenbei einen echten Bug
  gefixt: winzige 1-RTT-Pakete brauchen PADDING fürs HP-Sample (RFC 9001 §5.4.2, `PacketPadding`).
- ✅ **Connection Close & Draining** (RFC 9000 §10.2): `Close(TransportError, reason)` sendet ein
  CONNECTION_CLOSE und geht in den Closing-Zustand (nur noch CONNECTION_CLOSE, erneut je eingehendem
  Paket); Empfang eines CONNECTION_CLOSE → Draining (sendet nichts mehr, merkt `PeerCloseFrame`); nach
  3·PTO → Closed. `IsClosing`/`IsDraining`/`IsClosed` durchgereicht; H3Get schließt nach dem GET anständig,
  H3Server erkennt/reapt drainende Verbindungen. **Live über UDP bestätigt.**
- ✅ **Connection-ID-Rotation** (RFC 9000 §5.1, §19.15/§19.16): `ConnectionIdManager` verwaltet die
  lokal ausgegebenen (Peer→DCID) und die vom Peer angebotenen (wir→DCID) Connection IDs mit Sequenznummern.
  `IssueConnectionId()` sendet NEW_CONNECTION_ID (respektiert `active_connection_id_limit`);
  `RotateDestinationConnectionId()` wechselt die DCID und zieht die alte per RETIRE_CONNECTION_ID zurück;
  „Retire Prior To" und eingehende RETIRE werden behandelt. Der Empfang akzeptiert nur Pakete an eine
  aktive lokale CID. **Live über UDP bestätigt** (eigener Server gibt CID aus, Client rotiert → 2. GET
  unter neuer CID). Cloudflare bot in der kurzen Verbindung keine zusätzliche CID an (Server-Policy).
- ✅ **Stateless Reset** (RFC 9000 §10.3), **Empfang + Senden**:
  - **Empfang:** Tokens des Peers (aus NEW_CONNECTION_ID + `stateless_reset_token`-TP) werden gespeichert;
    ein nicht verarbeitbares Short-Header-Datagramm, dessen letzte 16 Bytes einem bekannten Token entsprechen
    (konstantzeitig), führt in Draining (`StatelessResetReceived`).
  - **Senden:** Der Server leitet seine Tokens jetzt aus der CID ab (`StatelessResetTokenGenerator` =
    HMAC-SHA256(geheim, CID)[0..16], §10.3.1), sodass sie nach Zustandsverlust neu berechenbar sind. Der
    Demux (H3Server) beantwortet ein 1-RTT-Paket zu **unbekannter** DCID mit `StatelessReset.BuildResponse`:
    Token aus der DCID rechnen, Reset **kleiner** als der Auslöser bauen (Loop-Vermeidung §10.3.3), nur auf
    Short-Header ab Mindestgröße. In-process end-to-end getestet (zustandsloser Responder mit geteiltem
    Geheimnis ⇒ Reset, den der Client erkennt) + Unit-Tests (Token-Determinismus, Größen-/Loop-Regeln).
    Der H3Server **persistiert das Geheimnis** (`--secret-file=`, Standard neben der Exe) ⇒ über Neustarts gleich
    (verifiziert: identische Bytes, „geladen"), sodass ein neu gestarteter Server für alte Verbindungen gültige
    Resets senden kann. Der Demux öffnet neue Verbindungen nur noch auf echte **Initial**-Pakete (RFC 9000 §5.2);
    Short-Header zu unbekannter CID ⇒ Reset, andere Long-Header ⇒ verworfen. (Ein Live-Cross-Restart-Demo ist
    nicht enthalten: der Ein-Socket-Client des Samples flush beim Ziel-Wechsel ein stale Initial statt eines
    1-RTT-Pakets — eine Sample-Orchestrierungs-Grenze, keine Frage der Protokoll-Logik.)
- ✅ **Schlüssel verwerfen nach dem Handshake** (RFC 9001 §4.9.1/§4.9.2): Der Endpoint verwirft die
  **Initial**-Keys (Client: sobald er ein Handshake-Paket gesendet hat; Server: sobald er eines verarbeitet
  hat) und die **Handshake**-Keys (sobald der Handshake bestätigt ist). **Handshake-Bestätigung** (§4.1.2):
  Server beim Abschluss; Client bei HANDSHAKE_DONE **oder** – zusätzlich, RFC-legitim (MAY) – sobald eines
  seiner **1-RTT-Pakete quittiert** wird (`OnOneRttPacketAcknowledged`, Vergleich gegen die erste 1-RTT-PN).
  So werden die Handshake-Keys ggf. schon vor einem verlorenen HANDSHAKE_DONE verworfen (robuster). `DiscardKeys`
  räumt Keys, ausstehende CRYPTO/Retransmits und den Loss-Recovery-Space (RFC 9002 §6.4, Bytes aus
  `bytes_in_flight`). **Behebt einen Bug:** ohne Discard sondierte ein PTO den Initial-Space und sendete den
  ClientHello nach dem Handshake als (gepolstertes) 1200-Byte-Initial erneut.
  Test `KeyDiscardTests` (nach dem Handshake unter PTO kein Initial/Handshake-Paket); Cloudflare-Live (normal,
  `--mlkem`, `--zerortt`) je Status 200. **Zeitpunkt gegen RFC 9001 §4.9.1 geprüft:** die Verwerfungspunkte sind
  exakt die vorgeschriebenen; **früher wäre RFC-widrig** (§4.9: die Gegenseite hätte „nicht das Gleiche getan",
  und man braucht die Initial-Keys noch, um den Peer-Initial zu acken) und brächte nichts (ACK + Finished im
  selben Flight). Zweiter Test sichert die Gegenrichtung ab (Client sendet den Initial-ACK des ServerHello ⇒
  ≥2 Initial-Pakete, also nicht zu früh verworfen). **Reordering-Fenster gegen RFC 9001 §4.9.2 geprüft:** die
  Handshake-Keys werden bei der Bestätigung **sofort** verworfen, **ohne** kurze Aufbewahrung für reorderte
  Pakete. Das ist Absicht der RFC: §4.9.2 ist ein bedingungsloses MUST **ohne** Reordering-Klausel, während
  §4.9.3 ein solches Fenster (~3×PTO) **nur für 0-RTT** ausdrücklich gewährt – dort erzeugt der Sender noch echte
  App-Daten, die reordern können; nach Handshake-Bestätigung trüge ein spätes Handshake-Paket dagegen nur schon
  Bekanntes (§4.9: neue Daten aufs höchste Level, unten nur ACK/CRYPTO-Retransmit). Test
  `HandshakeKeys_DiscardedImmediatelyOnConfirmation_NoReorderingWindow` (Keys im selben Moment der Bestätigung weg).
- ✅ **Key Update** (RFC 9001 §6): `TrafficKeys.Next` leitet `secret_<n+1>` über „quic ku" ab (Key/IV
  neu, **HP-Key unverändert**); `PacketProtection.RemoveHeaderProtection` trennt HP von AEAD, sodass das
  Key-Phase-Bit vor der Schlüsselwahl gelesen wird. `InitiateKeyUpdate()` rotiert die Send-Keys und kippt
  die Phase; ein gekipptes Bit beim Empfang rotiert Read- (und ggf. Send-)Keys, vorige Read-Keys werden
  kurz für Reordering behalten. `CurrentKeyPhase`/`KeyUpdateCount` durchgereicht. **Live gegen
  cloudflare-quic.com bestätigt** (zweites GET unter rotierten Schlüsseln, `H3Get --key-update`).
- ✅ **Transport-Error-Matrix** (RFC 9000 §11/§20.1) — KOMPLETT: Protokollverstöße der Gegenseite →
  CONNECTION_CLOSE mit korrektem Fehlercode statt Crash/still. FRAME_ENCODING_ERROR (Kodier-/Unbekannt-
  Fehler beim Frame-Parsen), STREAM_LIMIT_ERROR, stream-level FLOW_CONTROL_ERROR und FINAL_SIZE_ERROR
  (aus `StreamReceiveBuffer`), STREAM_STATE_ERROR (RESET_STREAM/STOP_SENDING auf falschen Stream-Arten,
  §19.4/§19.5). Nebenbei **PATH_CHALLENGE/PATH_RESPONSE** (§19.17/§19.18) — live gegen Cloudflare nötig.
  - ✅ **Connection-level FLOW_CONTROL_ERROR** (§4.1): die Summe der höchsten empfangenen Offsets ALLER
    Streams (bei RESET zählt die Final Size, §4.5) wird nach jedem STREAM-/RESET-Frame gegen das per
    initial_max_data/MAX_DATA gewährte Verbindungsfenster geprüft. End-to-end getestet (Test-Seam
    `OverrideConnSendLimitForTest` hebelt den braven Client aus) + Gegenprobe im Fenster.
  - ✅ **TRANSPORT_PARAMETER_ERROR** (§7.3/§7.4/§18.2): `TryDecode` lehnt ab — doppelte IDs (auch
    unbekannte), max_udp_payload_size < 1200, active_connection_id_limit < 2, Stream-Limits > 2^60,
    stateless_reset_token ≠ 16 B, CIDs > 20 B (vorher warf hier der ConnectionId-ctor — Fuzzer-Fund!).
    **§7.3-Authentifizierung** via `ValidatePeerTransportParameters` (Endpoint + Rollen-Overrides):
    initial_source_connection_id Pflicht + == Peer-SCID; Client prüft original_destination_connection_id
    (Pflicht + == erste DCID) und retry_source_connection_id (GENAU bei Retry, == Retry-SCID); Server
    lehnt server-only-Parameter vom Client ab (ODCID/RSCID/stateless_reset_token/preferred_address).
    End-to-end: „böser" Client mit ODCID ⇒ Server schließt 0x08, Client liest das Close.
  - ✅ **CONNECTION_CLOSE-Zustellung im Handshake repariert** (§10.2.3, vom neuen Test gefunden): vor
    bestätigtem Handshake ging das Close nur auf dem höchsten Level raus (ggf. 1-RTT) — ein Peer mit
    nur Initial-Keys konnte es NIE lesen. Jetzt: 1-RTT-Close erst nach Bestätigung, vorher koalesziert
    Initial+Handshake (Rückfall 1-RTT, wenn die Long-Header-Keys schon verworfen sind).
  - ✅ **Parser-Fuzzer** (deterministisch, feste Seeds ⇒ reproduzierbar): FrameParser, TransportParameters
    und Paket-Header-Parser werfen auf zufälligen UND mutierten gültigen Bytes (Bit-Flips/Kürzungen)
    NIEMALS — Fehler kommen als sauberes false/EncodingError. 4 Fuzz-Läufe à 2000–4000 Iterationen.
  - 11 neue Tests (TransportErrorMatrixTests + ParserFuzzTests). **Live:** Cloudflare-GET + 0-RTT,
    eigener Server mit --retry (RSCID-Pfad) und curl --http3 laufen mit den scharfen Prüfungen
    regressionsfrei durch.
- ✅ **RESET_STREAM / STOP_SENDING** (RFC 9000 §2.4, §3.5, §19.4/§19.5): `QuicStream.Reset(code)` bricht
  die Sendeseite ab (ungesendete Daten verworfen, Final Size = gesendete Bytes nach §4.5, danach keine
  STREAM-(Re)Transmissionen mehr); `AbortRead(code)` sendet STOP_SENDING. Empfang: RESET_STREAM validiert
  die Final Size (§4.5, unveränderlich; zählt voll als Flow-Control-Kredit) und markiert die Empfangsseite
  (`IsResetByPeer`/`PeerResetErrorCode`, nie „complete"); STOP_SENDING resettet die eigene Sendeseite
  automatisch mit kopiertem Fehlercode (§3.5 MUST). Beide Frame-Typen laufen zuverlässig über die Loss
  Recovery (retransmittierbar verfolgt; Verlust-Test per verworfenem Flight + PTO). In-process getestet
  (7 Tests: Puffer-Units, kopierter Code end-to-end, State-Fehler, HTTP/3-Cancellation, Loss).
- Grease: reservierte Frame-/Stream-Typen der Gegenseite tolerieren.

### ✅ Phase 9 — Performance & Nice-to-have — ABGESCHLOSSEN
*(0-RTT und die PQ-/Krypto-Kür sind hier historisch einsortiert und längst ✅; die async API, der
Zero-Allocation-Pfad, UDP-Batching und Window-Auto-Tuning ebenfalls.)*
- ✅ **Zero-Allocation-Pfad (Hot Paths)**: die pro Pump-Durchlauf teuren `List<byte>`-Puffer (deren
  `RemoveRange(0, n)` bei jedem Konsum ALLE Restbytes verschob — O(n²) über einen Transfer — und deren
  `ToArray()` je Durchlauf den ganzen Inhalt kopierte) durch **`ByteQueue`** ersetzt (Quic.Core:
  Head/Tail-Ringpuffer, amortisiert O(1) Anhängen/Konsumieren, Backing-Store wiederverwendet, Auslesen
  als `Span`/`Memory` ohne Kopie). Betroffen: `StreamSendBuffer` sowie alle HTTP/3-Stream-/Capsule-/
  QPACK-Uni-Stream-Puffer in `Http3ClientConnection`/`Http3ServerConnection`/`Http3Qpack`.
  `StreamReceiveBuffer.ReadAvailable` baut das Ergebnis jetzt in EINEM vorab dimensionierten Array
  (kein `MemoryStream`) und hat einen allokationsfreien Leer-Fast-Path. **Messung** (In-Process,
  `GC.GetAllocatedBytesForCurrentThread`, single-threaded ⇒ exakt): 300-KB-Download von **51,3 MiB auf
  7,0 MiB** gesenkt (7,3×; ~25 statt 179 B/Nutzbyte), Zeit ~55 → ~40 ms. Mess-Harness
  `PerformanceBenchTests` mit großzügiger Regressionswache (Download < 20 MiB).
- ✅ **UDP-Batching (GSO)**: `GsoBatcher` (Quic.Core) gruppiert die Datagramme eines Pump-Durchlaufs in
  UDP_SEGMENT-Batches — maximaler Lauf gleich großer Datagramme, optional plus ein kleineres
  Schluss-Segment (die Kernel-Regel), gedeckelt auf 64 Segmente / 65535 B. `UdpBatchSender` (Http3)
  sendet auf **Linux** je Batch mit einem einzigen `sendmsg` (Socket-Option UDP_SEGMENT via
  `SetRawSocketOption`, best-effort mit Fallback bei Ablehnung), auf allen anderen Plattformen eine
  schlanke Einzelsende-Schleife — auf dem Draht identisch, GSO spart nur Syscalls. Genutzt von den
  async-Fassaden `Http3Client`/`Http3Server`. Die reine Gruppierung ist deterministisch getestet
  (Rekonstruktion = ursprüngliche Datagramm-Folge, Segment-/Byte-Caps).
- ✅ **Window-Auto-Tuning (empfangsseitige Flow-Control-Fenster nach BDP)**: ein festes Fenster
  drosselt eine schnelle Verbindung auf ≈ Fenster/RTT — das BDP wächst mit der RTT. `ReceiveWindowTuner`
  (Quic.Streams) wendet die Chromium/quiche-Heuristik an: bei JEDEM fälligen Fenster-Update (Kredit
  unter halbem Fenster) wird die Zeit seit dem letzten Update gemessen; ist sie < 2×SmoothedRtt, war
  der Sender schneller als eine RTT am Fensterrand ⇒ Fenster verdoppeln (bis 16 MiB je Stream / 24 MiB
  je Verbindung). Verdrahtet in `CollectFlowControlFrames` — je Stream (`StreamReceiveBuffer.WindowTuner`)
  und für das Verbindungsfenster (`_connWindowTuner`); Startwerte bleiben die konfigurierten
  initial_max_data*. 5 Tests (Heuristik: Wachstum bei schneller/kein Wachstum bei langsamer Drainage,
  Deckelung, Limit ≥ Startwert; QUIC-Ende-zu-Ende: Verbindungsfenster wächst unter Dauertransfer).
  **Live:** Cloudflare-GET auch mit `--small` (48-KiB-Startfenster) über echte RTT, curl 200-KB-POST-
  Upload byte-genau geechot.
- ✅ **async API — Task-basierte Fassaden über echten Sockets** (`src/Http3/Http3Client.cs` /
  `Http3Server.cs`): der deterministische, transport-agnostische Kern bleibt unangetastet (alle Tests
  weiter synchron in-process); obendrauf besitzen die Fassaden den UDP-Socket und eine Hintergrund-
  Pump (ReceiveAsync + 20-ms-Timer-Tick, Task.WhenAny).
  - **Client** `Http3Client`: `ConnectAsync` (Handshake + InitializeHttp3, TimeoutException statt
    Hänger; SIO_UDP_CONNRESET auf Windows abgeschaltet), `SendAsync`/`GetAsync`/`PostAsync` (Request →
    `Task<Http3Response>`; endgültige Fehlschläge als `Http3RequestException` mit `IsRetryable` für
    GOAWAY-Rejections; CancellationToken ⇒ §4.1.1-Cancellation), `PerformAsync`/`QueryAsync`/
    `WaitUntilAsync` (serialisierter Zugriff für Datagramme/WebTransport/CONNECT), `CloseAsync`
    (graceful), `DisposeAsync`. Kern-Zugriffe strikt über ein SemaphoreSlim serialisiert.
  - **Server** `Http3Server`: bindet den Socket (Port 0 = ephemär, `Port`-Property), demuxt vorrangig
    über die Connection ID (Migration trifft dieselbe Verbindung), neue Verbindungen NUR auf echte
    Initial-Pakete (§5.2), optional Stateless Reset für unbekannte Short-Header (§10.3), Idle-Cleanup;
    voll konfigurierbar über eine `Func<Http3ServerConnection>`-Factory (WebTransport & Co. inklusive).
  - 5 Tests (Http3AsyncApiTests) über ECHTE Loopback-UDP-Sockets: GET, drei parallele Requests auf
    einer Verbindung, POST-Echo, Timeout gegen toten Port, Query/WaitUntil.
- ✅ **0-RTT (RFC 8446 §2.3 / RFC 9001 §4) — vollständig**:
  - **Phase A — Session Resumption (PSK)**: NewSessionTicket (Ausstellen + Parsen), resumption_master_secret /
    Resumption-PSK, `pre_shared_key` mit **Binder** (HMAC über den abgeschnittenen ClientHello, RFC 8446
    §4.2.11.2), `psk_key_exchange_modes` (immer gesendet ⇒ Server stellt Tickets aus), serverseitiger
    Ticket-Store + Binder-Prüfung, Handshake ohne Zertifikat.
  - **Phase B — Early Data**: `early_data`-Extension (ClientHello + EncryptedExtensions-Bestätigung),
    `client_early_traffic_secret`, eigener **0-RTT-Schlüsselsatz** (im Application-PN-Space), **0-RTT-Pakete**
    (Long Header 0x01) — der Client sendet die HTTP/3-Anfrage als Early Data **vor** dem Handshake-Abschluss,
    der Server akzeptiert und verarbeitet sie. Byte-genau interop **live gegen cloudflare-quic.com**
    (`H3Get --zerortt` → „0-RTT AKZEPTIERT", 126 KB, Status 200) sowie eigener Server über UDP + In-Process-Test.
    **0-RTT-Keys verwerfen** (RFC 9001 §4.9.3): der Client verwirft seinen 0-RTT-Schlüsselsatz, sobald die
    1-RTT-Keys installiert sind (`MaybeInstallApplicationKeys`, nur Client) — danach sendet er keine 0-RTT-Pakete
    mehr (§5.6) und empfängt selbst nie welche, die Keys sind nutzlos; sofortiges Verwerfen minimiert das
    Angriffsfenster. Test `Client_DiscardsZeroRttKeys_OnInstallingOneRttKeys`. **Reordering geprüft:** beim Client
    gibt es dafür bewusst **kein** Aufbewahrungsfenster (§4.9.3 „no use after that moment"): er hat keinen
    0-RTT-Read-Pfad — reorderte/verspätete Pakete werden mit Initial-/Handshake-/1-RTT-Read-Keys entschützt, und
    verlorene 0-RTT-Daten laufen über 1-RTT (Application-Retransmit-Queue), nie neu als 0-RTT. Nur der **Server**
    (Empfänger) braucht das kurze Fenster.
    Der **Server** verwirft seine 0-RTT-Read-Keys mit anderem Auslöser: er behält sie nach dem **ersten empfangenen
    1-RTT-Paket** (echter Short Header ⇒ `DeliverApplicationFrames`) noch kurz für reorderte 0-RTT-Pakete und
    verwirft sie dann „within a short time", RECOMMENDED **3×PTO** (`MaybeDiscardServerZeroRttKeys`, rein
    zeitgesteuert — auch ohne weiteren Verkehr über `CheckLossDetectionTimeout` ausgelöst).
    **Frühere Verwerfung bei vollständigem Empfang** (§4.9.3 letzter Satz, „A server MAY discard 0-RTT keys earlier
    if it determines that it has received all 0-RTT packets, … by keeping track of missing packet numbers"): Sind
    die Application-Paketnummern ab 0 **lückenlos** (`PacketNumberSpace.IsContiguousFromZero`, d. h. `Count = Max+1`)
    und wurde bereits ein 1-RTT-Paket empfangen (Obergrenze der 0-RTT-PNs bekannt, da 0-RTT-PNs alle darunter
    liegen), kann kein reordertes 0-RTT-Paket mehr ausstehen ⇒ `MaybeDiscardServerZeroRttKeysIfComplete` verwirft
    sofort, ohne die 3×PTO-Frist abzuwarten. Geprüft bei jedem empfangenen Application-Paket (1-RTT über
    `DeliverApplicationFrames`, reorderte 0-RTT über `DecryptAndHandle`). Tests
    `Server_DiscardsZeroRttKeysEarly_WhenAllPacketsReceived_NoGap` (verlustfrei ⇒ sofort weg trotz 5-min-Frist) und
    `Server_RetainsZeroRttKeys_UntilTimeout_WhenPacketNumberGapPersists` (PN-Lücke ⇒ Fallback auf die Frist).
    **Verbindungsende:** endet die Verbindung, bevor die 0-RTT-Read-Keys regulär verworfen wurden (kurzlebige
    Verbindung vor Fristablauf/Lückenfreiheit), gibt `Dispose()` sie frei (behoben: sie fehlten bisher in der
    Key-Freigabe neben `WriteKeys`/`ReadKeys`/`_nextAppReadKeys`/`_prevAppReadKeys`). Test
    `Server_DiscardsZeroRttKeys_OnDispose`.
  - **0-RTT-Ablehnung → 1-RTT-Retry** (RFC 9001 §4.6.2): weil 0-RTT im Application-PN-Space liegt, greift schon
    die normale Loss Recovery (nie bestätigte 0-RTT-Pakete ⇒ Frames über 1-RTT retransmittiert). Zusätzlich
    **proaktiv**: erkennt der Client die Ablehnung (kein early_data in EE), verschiebt er die 0-RTT-Frames sofort
    in die 1-RTT-Retransmit-Queue (`LossRecovery.OnZeroRttRejected`), ohne auf Zeitschwelle/PTO zu warten und
    ohne Doppelsenden. In-Process-Test (Server lehnt ab ⇒ Anfrage läuft trotzdem über 1-RTT durch, Status 200).
    **Handshake-Keys nach 0-RTT-Ablehnung geprüft** (RFC 9001 §4.9.2 + §4.1.2): Der Handshake-Key-Discard bleibt
    korrekt, obwohl 0-RTT und 1-RTT denselben Application-PN-Space teilen. Die §4.1.2-Bestätigung (via 1-RTT-ACK)
    zählt nur ein **echtes** 1-RTT-Paket: `_firstOneRttPacketNumber` wird ausschließlich in `BuildApplicationPackets`
    gesetzt (nie in `BuildZeroRttPackets`), und da 0-RTT-PNs stets kleiner sind, impliziert `LargestAck ≥` dieser PN
    nachweislich die Quittung eines 1-RTT-Pakets – ein (akzeptierter oder verirrter) 0-RTT-ACK bestätigt den
    Handshake **nie** zu früh. Kein Verhaltensänderung nötig; Regressions-Test
    `RejectedEarlyData_HandshakeStillConfirmsAndDiscardsHandshakeKeys_ViaOneRttAck` (0-RTT abgelehnt UND
    HANDSHAKE_DONE unterdrückt ⇒ Client bestätigt per 1-RTT-ACK und verwirft die Handshake-Keys).
- ✅ **ECN** (RFC 9000 §13.4 / RFC 9002 §7.3): Der Empfänger zählt die ECN-Codepoints (ECT0/ECT1/CE) je
  Packet-Number-Space (`PacketNumberSpace.RecordReceived(pn, ecn)`) und meldet sie im ACK-Frame (Typ 0x03,
  war schon serialisierbar). Der Sender behandelt einen gestiegenen CE-Zähler wie einen Verlust und halbiert
  das Fenster (`LossRecovery` ProcessECN → `NewReno.OnEcnCongestionEvent`, nur einmal pro Recovery-Periode).
  Der Codepoint wird über `ProcessDatagram(dg, ecn)` durchgereicht. In-Process getestet (Zählung/Meldung,
  CE-Reaktion, End-to-End cwnd-Rückgang). **Grenze:** das eigentliche IP-Ebenen-Marking (ECT setzen/CE lesen)
  ist mit BCL-UDP-Sockets — v. a. auf Windows (IP_TOS eingeschränkt) — nicht praktikabel; das ist reine
  Transportschicht, die Protokoll-Logik ist vollständig.
- ✅ Krypto-Roadmap **komplett**: X25519, X448, ChaCha20-Poly1305, Ed25519, Ed448 (Primitive aus
  BouncyCastle) **und** der PQ-Hybrid X25519MLKEM768 (ML-KEM aus der BCL + X25519) — live/interop bestätigt.
- ✅ **ML-DSA-Signaturen (FIPS 204, draft-ietf-tls-mldsa)** — Post-Quantum-Serverzertifikate, komplett
  BCL-nativ (.NET 10 `MLDsa` + `CertificateRequest`; X509-PQC-APIs punktuell per SYSLIB5006-Pragma):
  SignatureSchemes mldsa44/65/87 (0x0904–0x0906, pure, FIPS-204-Kontext leer — §4),
  `ServerCertificate.CreateSelfSignedMLDsa` (Standard ML-DSA-65), Client verifiziert CertificateVerify
  inkl. Parameterstärke-Check (SPKI-OID 2.16.840.1.101.3.4.3.17/.18/.19 muss zum Scheme passen) und
  bietet die drei Schemes in signature_algorithms an. 2 Tests (Handshake + alle drei Parametersätze;
  `MLDsa.IsSupported`-Guard). **Live über UDP:** `H3Server --mldsa` + `H3Get -k` → Status 200; und
  **voll post-quantum** `--mldsa --mlkem` beidseitig: X25519MLKEM768-KEX + ML-DSA-65-Signatur → 200.
- ✅ **Connection Migration** (RFC 9000 §8.2/§9): Pfadvalidierung (`InitiatePathValidation` sendet
  PATH_CHALLENGE mit 8 Zufallsbytes, passendes PATH_RESPONSE → `PathValidated`, mit 3·PTO-Frist);
  PATH_CHALLENGE wird beantwortet. `OwnsConnectionId` erlaubt CID-basiertes Demuxing. **Live über UDP:**
  H3Server demuxt über die Connection ID; `H3Get --migrate` wechselt den lokalen Port → der Server erkennt
  die Migration, validiert den neuen Pfad, das zweite GET läuft über den neuen Pfad durch. In-process
  getestet (Client-/Server-initiiert + Ablauf).
- ✅ **Anti-Amplification-Limit** (RFC 9000 §8.1): Vor der Adressvalidierung sendet der Server höchstens
  3× so viele Bytes, wie er empfangen hat (`_amplificationReceived/_amplificationSent`, Budget an
  `BuildLevelPacket` durchgereicht; CRYPTO bleibt persistent gepuffert, falls das Budget zurückstellt).
  Validiert bei erstem entschlüsseltem Handshake-Paket oder gültigem Retry-Token; der Client ist per
  Konstruktion validiert. In-process getestet (Invariante gesendet ≤ 3×empfangen), live grün (eigener
  Server unter dem Limit, Cloudflare/`--loss` unbeeinträchtigt).

---

## Test- & Debug-Strategie (von Anfang an!)

1. **RFC-Testvektoren als Unit-Tests:** RFC 9001 Appendix A (Initial-Pakete, Retry-Tag,
   ChaCha20-Vektoren), RFC 8448 (TLS-Key-Schedule), RFC 7541 Appendix C (Huffman).
2. **`SSLKEYLOGFILE`-Export** implementieren → Wireshark kann eigene QUIC-Pakete entschlüsseln.
   Unbezahlbar beim Debuggen; ~30 Zeilen Code.
3. **qlog** (JSON-Ereignislog pro Verbindung) früh einbauen → Visualisierung mit qvis.
   Mindestens: packet_sent/received, frames, loss, recovery-Metriken.
4. **Lossy-UDP-Proxy** im Testprojekt (Drop/Reorder/Duplicate/Delay konfigurierbar,
   seed-basiert deterministisch) für Recovery-Tests ohne externe Tools.
5. **Interop-Ziele (Client-Seite) ✅ 8 Stacks:** quiche (Cloudflare), nginx, Google QUIC, mvfst (Meta),
   lsquic (LiteSpeed), msquic (Microsoft/outlook), quic-go (Caddy), Akamai — je Status 2xx/3xx mit voller
   Cert-Prüfung. **Server-Seite:** `curl --http3` ✅ (ngtcp2/LibreSSL unter Windows + OpenSSL-QUIC unter
   WSL/Debian); Firefox/Chrome offen (brauchen vertrauenswürdige Zertifikate).
6. **State-Machine-Tests in-process:** eigener Client gegen eigenen Server ohne echtes
   Netzwerk (In-Memory-„UDP"), damit Handshake-Tests in Millisekunden laufen.

## Krypto-Roadmap

Gestaffelt nach Interop-Nutzen und Aufwand.

**Grundsatz (wichtig):** „From scratch" meint die **Protokoll-Logik**, nicht die Krypto-Primitive.
Wir bauen QUIC/TLS-Handshake/QPACK/HTTP/3 selbst und rufen für Primitive geprüfte, konstantzeitige
Implementierungen auf — bei AES/P-256 die BCL, bei den BCL-Lücken (X25519/Ed25519) eine schlanke,
auditierte Bibliothek. **Kurven-Arithmetik oder Cipher-Runden mit geheimnisabhängigen Table-Lookups
selbst zu schreiben ist ausdrücklich unerwünscht** (Seitenkanal-/Sicherheitsrisiko, und nicht der
Lerninhalt des Projekts). **Eine bewusste Ausnahme:** der rohe ChaCha20-Block für die Header Protection
(siehe Krypto-Roadmap Stufe 2.3) — ARX/konstant-zeitig ohne Table-Lookups, und die Bibliotheken bieten
keinen Einzelblock bei beliebigem Counter, den RFC 9001 §5.4.4 verlangt.
Alles hinter den Abstraktionen (`IPacketProtection`, Key-Exchange/Signatur-Interfaces), damit der
Transport-Code die Quelle nie sieht und sie austauschbar bleibt.

Bibliotheks-Optionen für die Primitive-Lücken (v2), pragmatisch abgewogen:
- **BouncyCastle.Cryptography** — rein managed, deckt X25519/Ed25519/ChaCha20/Ed448/X448 ab; eine
  Dependency, aber groß. Nur die Primitive nutzen, **nicht** den TLS-Stack.
- **libsodium/NSec** — nativ, sehr schnell und breit auditiert; für X25519/Ed25519/ChaCha20.
- Bleibt Test-Orakel-tauglich: gegen die Primitive lassen sich RFC-Vektoren gegenprüfen.

**Stufe 1 — v1, Pflicht (reine BCL):** ✅ komplett
- ✅ AEAD: AES-128-GCM (`AesGcm`); AES-256-GCM (`TrafficKeys` parametrisiert)
- ✅ Key Exchange: `secp256r1` (P-256) via `ECDiffieHellman` (`EcdheKeyExchange`)
- ✅ Signaturen: RSA-PSS, ECDSA P-256/P-384 — CertificateVerify wird IMMER geprüft (Phase 2),
  Kette + Hostname gemäß `CertificateValidationOptions`
- → deckt 100 % der realen HTTP/3-Server ab

**Stufe 2 — v2, Kür (Primitive aus Bibliothek + BCL-PQ):**
1. ✅ **X25519** (RFC 7748) — Primitiv aus BouncyCastle (`X25519KeyExchange`), gekapselt hinter
   `IKeyExchange`. Client bietet X25519 zuerst an; **live gegen cloudflare-quic.com auf X25519
   geeinigt**. HelloRetryRequest (Client + Server) implementiert und in-process getestet.
2. ✅ **X25519MLKEM768** (Hybrid-PQ-Key-Exchange, Codepoint 0x11EC/4588, draft-ietf-tls-ecdhe-mlkem) —
   **ML-KEM-768 aus der BCL** (`MLKem` in .NET 10, stabil, keine Experimental-Warnung), X25519 aus
   BouncyCastle. Wir schreiben die **Hybrid-Kombination** selbst (Protokoll-Logik): Client-Share
   ek(1184)‖x25519(32)=1216, Server-Share ct(1088)‖x25519(32)=1120, Secret ss_mlkem(32)‖ss_x25519(32)=64
   — **ML-KEM-Teil zuerst** (historischer „reversed"-Quirk für X25519MLKEM768). Da ein KEM asymmetrisch
   ist (Server encapsuliert, Client decapsuliert), bekam `IKeyExchange` eine `Encapsulate`-Methode
   (Default = klassisches DH). In-Process-Handshake grün; **live über UDP gegen den eigenen Server
   (`--mlkem`) und byte-genau interop gegen cloudflare-quic.com** (Gruppe X25519MlKem768, volle Kette,
   Status 200, 126 KB) — falsche Byte-Reihenfolge hätte den Finished-MAC brechen lassen. Motivation:
   „harvest now, decrypt later"; Chrome/Firefox/Cloudflare fahren den Hybrid seit 2024/25.
3. ✅ **ChaCha20-Poly1305** — `ChaCha20Poly1305` (BCL) für AEAD; der rohe ChaCha20-Block für die
   Header Protection ist **bewusst selbst geschrieben** (`Crypto/ChaCha20.cs`). Begründung: BCL wie
   BouncyCastle bieten ChaCha20 nur als *Stream-/AEAD*-Cipher (Counter startet bei 0), aber
   RFC 9001 §5.4.4 braucht einen *einzelnen Block bei beliebigem 32-Bit-Counter* (aus dem Sample) —
   dafür gibt es keinen sauberen API-Aufruf. Das Seitenkanal-Argument der übrigen Bibliotheks-Primitive
   greift hier kaum: ChaCha20 ist ARX (add-rotate-xor), konstant-zeitig per Konstruktion, ohne
   geheimnisabhängige Table-Lookups (anders als AES-S-Boxen oder X25519-Feldarithmetik). Der Block ist
   byte-genau gegen RFC 8439 §2.3.2 und RFC 9001 §A.5 (`aefefe7d03`) verifiziert und live bestätigt.
4. ✅ **Ed25519** (RFC 8032) — Signaturen; Primitiv aus BouncyCastle (`Ed25519Signature`), gekapselt
   wie X25519. `SignatureScheme ed25519` (0x0807) wird im ClientHello angeboten und clientseitig
   verifiziert (PureEdDSA, kein Vor-Hash; Public Key aus dem Leaf-SPKI). `ServerCertificate` kann ein
   selbstsigniertes Ed25519-Zertifikat erzeugen (Schlüssel/Signatur aus BouncyCastle, TBSCertificate-Bau
   über einen `X509SignatureGenerator` der BCL). RFC 8032 §7.1 byte-genau (Public Key + Signatur, Test 1+2);
   In-Process-Handshake mit Ed25519-Cert grün, und live über UDP bestätigt (`H3Server --ed25519` + `H3Get -k`
   → Signatur geprüft, Status 200). Im WebPKI kaum verbreitet, daher Kür.

**Stufe 3 — optional (Vollständigkeit):**
- ✅ **X448** (RFC 7748, Curve448/„Goldilocks"): Primitiv aus BouncyCastle (`X448KeyExchange`, hinter
  `IKeyExchange` wie X25519), Named Group `x448` (0x001e), 56-Byte-Key/-Secret. `KeyExchange.Create`/
  `IsSupported` kennen X448; die Named Groups sind jetzt durch die ganze API durchgereicht
  (`Http3ClientConnection` `keyExchangeGroups`, `Http3ServerConnection` `preferredGroups`). RFC 7748 §5.2
  byte-genau (beide Einzelvektoren), In-Process-Handshake einigt sich auf X448, und live über UDP bestätigt
  (`H3Server --x448` + `H3Get --x448 -k` → Gruppe X448, Status 200). Im Feld praktisch nicht anzutreffen
  (Browser bieten x448 nicht an), daher reine Vollständigkeit.
- ✅ **Ed448** (RFC 8032, edwards448/SHAKE256): Signaturprimitiv aus BouncyCastle (`Ed448Signature`, wie
  Ed25519 gekapselt), `SignatureScheme ed448` (0x0808), PureEdDSA mit **leerem Kontext** (TLS 1.3), Public Key
  57 Byte / Signatur 114 Byte. Client verifiziert die CertificateVerify-Signatur (Public Key aus dem Leaf-SPKI,
  id-Ed448 1.3.101.113); `ServerCertificate.CreateSelfSignedEd448` baut ein Ed448-Zertifikat über denselben
  `X509SignatureGenerator`-Weg wie Ed25519. RFC 8032 §7.4 byte-genau (Public Key + Signatur, Blank + 1-octet);
  In-Process-Handshake mit Ed448-Cert grün, und live über UDP bestätigt (`H3Server --ed448` + `H3Get -k`
  → Signatur geprüft, Status 200). Im Feld nicht anzutreffen (WebPKI stellt keine Ed448-Zertifikate aus),
  daher reine Vollständigkeit.
- **PQ-Signaturen (ML-DSA/SLH-DSA)**: `MLDsa`/`SlhDsa`/`CompositeMLDsa` sind in .NET 10 bereits
  vorhanden — nutzbar, sobald die WebPKI PQ-Zertifikate ausstellt. Bis dahin beobachten.

**Hinweis fürs Design:** Krypto-Aufrufe im QUIC-Layer hinter ein schmales Interface legen
(`IPacketProtection`: Seal/Open/HeaderMask; analog für Key Exchange und Signaturen), damit
neue Suiten/Gruppen ohne Änderungen am Transport-Code einsteckbar sind.

## Bewusste Auslassungen (Scope-Kontrolle)

*(Historische v1-Auslassungen inzwischen nachgerüstet: ChaCha20-Poly1305, X25519/X448/Hybrid-PQ,
0-RTT und die dynamische QPACK-Tabelle sind längst umgesetzt — siehe Krypto-Roadmap und Phasen 6/9.
Ebenso ALLE HTTP/3-Extensions: Priorities (9218), WebSockets (9220), HTTP-Datagramme (9297/9221),
WebTransport (draft-13) — siehe Phase 7.)*

- **Kein** Server-Push (MAY; PUSH-Frames/-Streams werden validierend abgewiesen), **kein**
  klassisches CONNECT-Proxying (gültiger CONNECT ohne :protocol ⇒ 501).
- **Kein** CUBIC/BBR (NewReno reicht), **keine** Multipath-Erweiterung.
- Kein HTTP/1.1/2-Fallback, kein Alt-Svc-Handling — reines HTTP/3.
- WebTransport (draft-13) ist inzwischen VOLLSTÄNDIG umgesetzt — inkl. der einst offenen Randstücke
  RESET_STREAM_AT, WT-Protocol-Negotiation (§3.3) und Keying-Material-Exporter (§4.7), siehe Phase 7.

## Empfohlene Reihenfolge der ersten Schritte

1. ✅ Phase 0 + VarInt mit Tests (halber Tag).
2. ✅ RFC-9001-Appendix-A-Vektoren zum Laufen bringen (Initial Secrets, AEAD, Header Protection) —
   damit steht das ganze Krypto-Fundament nachweislich korrekt.
3. ✅ ClientHello bauen, Initial-Paket an cloudflare-quic.com senden, ServerHello zurückparsen —
   ab hier gibt es bei jedem Schritt echtes Server-Feedback statt Trockenübungen.

**Als Nächstes (Stand 2026-07-23):** ALLE Phasen (0–9) sind abgeschlossen — RFC-9114-Feature-Audit,
Transport-Error-Matrix, alle Extensions (Priorities/WebSockets/Datagramme/WebTransport komplett inkl.
RESET_STREAM_AT), PQ-Krypto (ML-KEM-Hybrid + ML-DSA), async API, curl-Interop und die Performance-Kür
(Zero-Alloc, UDP-Batching/GSO, Window-Auto-Tuning). Die Client-Interop ist gegen **8 unabhängige
QUIC-Stacks** bestätigt (quiche/nginx/Google/mvfst/lsquic/msquic/quic-go/Akamai — Matrix bei M2).
Verbleibende Kür: Browser-Interop (Firefox/Chrome, brauchen vertrauenswürdige Zertifikate) oder die
Rückführung nach Hermod (Deduplizierung der WebSocket-Kopien).

## Referenzen

- RFC 9000 — QUIC: Transport
- RFC 9001 — Using TLS to Secure QUIC (inkl. Testvektoren in Appendix A)
- RFC 9002 — QUIC Loss Detection and Congestion Control
- RFC 8446 — TLS 1.3 (+ RFC 8448 Beispiel-Traces)
- RFC 9114 — HTTP/3
- RFC 9204 — QPACK (+ RFC 7541 Appendix B: Huffman-Tabelle)
- RFC 9369 — QUIC Version 2 (nur zur Kenntnis; v1 reicht)
- Vergleichsimplementierungen zum Nachschlagen (nicht als Dependency!):
  quiche (Cloudflare, Rust), ngtcp2 (C), quic-go (Go), msquic (C).
