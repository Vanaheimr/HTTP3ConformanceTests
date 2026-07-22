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
  Quic.Core/             # Gemeinsame Primitive (VarInt aus RFC 9000 §16, Span-Buffer) – von allen Schichten genutzt
    VarInt.cs            # QUIC Variable-Length Integers (RFC 9000 §16)
    Buffers/             # Pooling, Reader/Writer über Span<byte>
  Quic.Tls/              # QUIC-TLS-Handshake-Bindung (RFC 8446 + 9001) – TLS 1.3 im QUIC-Profil,
                         # ohne Record-Layer; liefert Handshake-Nachrichten + Secrets an Quic
    Messages/            # ClientHello, ServerHello, EncryptedExtensions, ...
    Extensions/          # SNI, ALPN, KeyShare, SupportedVersions, quic_transport_parameters
    KeySchedule.cs       # HKDF-Expand-Label, Secrets, Transcript-Hash
    HandshakeMachine.cs  # Client- & Server-Zustandsautomat
  Quic/                  # QUIC Transport (RFC 9000/9001/9002); referenziert Quic.Tls (Einweg)
    Packets/             # Long/Short Header, Packet Number Codec
    Crypto/              # Initial Secrets, Packet/Header Protection, Key Update
    Frames/              # Alle Frame-Typen
    QuicConnection.cs    # Verbindungs-Zustandsautomat
    QuicStream.cs        # Streams + Flow Control
    Recovery/            # RTT, Loss Detection, PTO, NewReno (RFC 9002)
    Udp/                 # Socket-Loop, Demultiplexing per Connection-ID
  Http3.Qpack/           # QPACK (RFC 9204)
    StaticTable.cs
    Huffman.cs           # Tabelle aus RFC 7541 Appendix B
    Encoder.cs / Decoder.cs
  Http3/                 # HTTP/3 (RFC 9114) + öffentliche API
    Http3Connection.cs   # Control Streams, SETTINGS
    Http3Client.cs / Http3Server.cs
tests/
  Http3.Tests/           # Unit-Tests mit RFC-Testvektoren
samples/
  H3Get/                 # CLI: GET gegen öffentliche HTTP/3-Server
  H3Server/              # Minimaler Demo-Server

Namespaces: org.GraphDefined.Vanaheimr.Hermod.Quic (+ .Tls/.Core/…) für den QUIC-Transport —
NEBEN, nicht unter HTTP/3; org.GraphDefined.Vanaheimr.Hermod.HTTP3 (+ .Qpack/.Tests) für die
HTTP/3-Schicht. Projekt-/Assemblynamen bleiben die kurzen. Usings in #region Usings-Blöcken.
```

---

## Phasen

**Status-Legende:** ✅ fertig · 🔶 teilweise · ⬜ offen. Stand: 263 Tests grün, Meilensteine M1–M3
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

### 🔶 Phase 2 — TLS-1.3-Handshake-Engine (RFC 8446, nur was QUIC braucht)
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
- ⬜ Client- und Server-Seite als expliziter Zustandsautomat; Interface zum QUIC-Layer:
  „hier sind CRYPTO-Bytes auf Level X rein" / „hier sind CRYPTO-Bytes für Level Y raus" /
  „neue Schlüssel für Level Z verfügbar" (analog zum ngtcp2/quiche-Modell).
- ✅ **Prüfstein bestanden:** Key-Schedule-Testvektoren aus **RFC 8448** (TLS 1.3 Traces) werden
  byte-genau nachgerechnet (Early/Handshake Secret, c/s hs traffic, Traffic-Key-Ableitung).

### 🔶 Phase 3 — QUIC-Verbindungsaufbau (RFC 9000 §5–§7, §12–§14)
Ziel: Vollständiger Handshake gegen einen echten Server (z. B. `cloudflare-quic.com`).
- ✅ Frames der ersten Stunde: `PADDING`, `PING`, `ACK`, `CRYPTO`, `CONNECTION_CLOSE` (+ STREAM,
  HANDSHAKE_DONE). Parsen/Serialisieren gegen RFC-9001-A.3-Payload verifiziert.
- 🔶 Encryption Levels: ✅ Initial (Schlüssel + Pakete); ⬜ Handshake/1-RTT-Schlüssel (aus Phase 2b).
  ✅ Coalesced Packets (mehrere QUIC-Pakete pro UDP-Datagramm) werden geparst.
- 🔶 Verbindungs-Zustandsautomat: ✅ wiederverwendbare `QuicClientConnection` (Client-seitig) mit
  Encryption-Levels, Packet-Number-Spaces (`PacketNumberSpace`), CRYPTO-Reassemblierung und
  TLS-Engine (`TlsClientHandshake`, „CRYPTO rein / CRYPTO + Keys raus"-Modell) — treibt den
  Handshake bis HANDSHAKE_DONE; ✅ expliziter Zustand Closing/Draining/Closed, Idle-Timeout und
  Server-Seite (siehe Phase 8 / M3).
- 🔶 ACK-Erzeugung: ✅ Ranges aus empfangenen Paketnummern (`AckFrame.FromPacketNumbers`),
  im Handshake live gesendet; ⬜ ack_delay, ACK-Verarbeitung/Loss-Detection, dauerhaftes ACKen.
- 🔶 Transport-Parameter: ✅ Encode/Decode (`TransportParameters`); ⬜ echtes Aushandeln/Anwenden
  der Limits im Verbindungszustand.
- ✅ **CRYPTO-Daten paketübergreifend**: Empfang (`CryptoStreamAssembler`, offset-basiert,
  ungeordnet/überlappend — Cloudflare-Zertifikatskette über 5 Handshake-Pakete reassembliert) **und
  Senden** (`AppendLevelPackets` verteilt ausgehende CRYPTO offset-korrekt auf mehrere Initial-/Handshake-
  Pakete, je ≤ MTU, `MaxCryptoDataPerPacket = 1000`). Der PQ-Hybrid-ClientHello (X25519MLKEM768,
  ~1450 Byte) geht so als **zwei** ≤1252-Byte-Initials raus (statt eines Übergroßdatagramms); Regressionstest
  über den Datagramm-Pfad + live gegen Cloudflare bestätigt (normal **und** `--mlkem`, je Status 200).
- 🔶 UDP-Loop: ✅ einfaches Senden/Empfangen (Sample `H3Get`); ⬜ Demultiplexing per Destination
  Connection ID, Single-Writer-Prinzip pro Verbindung (Channel/Lock-freie Queue).
- ✅ Client-Initial auf ≥ 1200 Bytes padden (`InitialPacketFactory`); ⬜ Anti-Amplification-Limit
  (3×) serverseitig.
- ✅ **Meilenstein M1 erreicht:** **Vollständiger** Handshake mit cloudflare-quic.com — ClientHello
  → ServerHello → Server-Flight entschlüsselt & Finished verifiziert → eigener Finished + ACKs
  gesendet → **HANDSHAKE_DONE** in einem 1-RTT-Paket empfangen. Handshake abgeschlossen, 1-RTT-Keys
  aktiv. ✅ Sauberes `CONNECTION_CLOSE`/Draining und Idle-Timeout inzwischen umgesetzt (Phase 8).
- ✅ ACK-Erzeugung aus empfangenen Paketnummern (`AckFrame.FromPacketNumbers`); NEW_TOKEN /
  NEW_CONNECTION_ID / RETIRE_CONNECTION_ID parsen (1-RTT-Flight).

### 🔶 Phase 4 — Streams & Flow Control (RFC 9000 §2–§4, §19)
- ✅ `STREAM`-Frames (Offset/FIN/Length-Varianten), Reassemblierung out-of-order Daten
  (`StreamReceiveBuffer` mit Final-Size/Flow-Control-Prüfung; `StreamSendBuffer`).
- ✅ Bidirektionale + unidirektionale Streams, Stream-ID-Vergabe (`StreamId`, Bit-Kodierung).
  Server-Streams (HTTP/3-Control + QPACK) von cloudflare-quic.com live reassembliert.
- 🔶 Flow Control: ✅ Frames `MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS`/`DATA_BLOCKED`/
  `STREAM_DATA_BLOCKED`/`STREAMS_BLOCKED`; ✅ Sende-Fensterbeachtung (Stream + Verbindung),
  Peer-Limits aus EncryptedExtensions dekodiert; ⬜ Empfangs-seitiges MAX_*-Nachführen (Window-Auto-Tuning).
- ✅ `RESET_STREAM` / `STOP_SENDING` (parse/write); ⬜ vollständige Stream-Zustandsautomaten (§3).
- 🔶 Stream-API: `QuicStream` (`Write`/`Finish`/`Read`); ⬜ async/Backpressure-API.
- ✅ 1-RTT-Sendepfad (`ShortHeader.Build`) — App-Pakete mit ACK + STREAM-Frames.

### 🔶 Phase 5 — Loss Detection & Congestion Control (RFC 9002)
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

### 🔶 Phase 6 — QPACK (RFC 9204), minimal aber korrekt
- ✅ **Stufe 1 (reicht für volle Interop):** Encoder/Decoder ohne dynamische Tabelle —
  statische Tabelle (99 Einträge, `QpackStaticTable`) + Literale, Huffman (`Huffman`, Tabelle aus
  RFC 7541 App. B, per Skript generiert), N-Bit-Integer und String-Codec (`QpackPrimitives`).
  Verifiziert: RFC-9204-B.1-Beispiel (Decode), RFC-7541-Huffman-Vektoren, Round-Trips typischer
  Request-Header. `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` wird angesagt → Peer bleibt auch statisch;
  Verweise auf die dynamische Tabelle werden abgelehnt (`QpackResult.DynamicTableReference`).
- ⬜ Encoder-/Decoder-Streams (Pflicht in HTTP/3, bleiben bei Kapazität 0 praktisch leer) — mit Phase 7.
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

### 🔶 Phase 7 — HTTP/3 (RFC 9114)
- ✅ Unidirektionale Streams mit Typ-Präfix: Control (0x00), QPACK Encoder (0x02) /
  Decoder (0x03); Control-Stream geöffnet, `SETTINGS` als erstes Frame.
- ✅ Frames: `DATA`, `HEADERS`, `SETTINGS` (inkrementelles Parsen, unbekannte Frames ignoriert –
  Greasing). ⬜ `GOAWAY`, `MAX_PUSH_ID`, CANCEL_PUSH.
- ✅ Request/Response: Pseudo-Header (`:method`/`:scheme`/`:authority`/`:path`/`:status`),
  Mapping Request ↔ bidirektionaler Stream; ⬜ strikte Pseudo-Header-Validierung.
- ⬜ Fehlerbehandlung: H3-Fehlercodes auf QUIC-Fehler mappen (Stream- vs. Connection-Error).
- 🔶 Öffentliche API: ✅ `Http3ClientConnection` (`InitializeHttp3`/`SendRequest`/`TryGetResponse`,
  transport-agnostisch); ⬜ ergonomischer `Http3Client.GetAsync(uri)`; ⬜ Server-Seite.
- ✅ Server-Push weggelassen.
- ✅ **Meilenstein M2 erreicht:** `GET https://cloudflare-quic.com/` liefert Status 200 + 126 KB
  HTML über den eigenen Stack (QPACK-dekodierte Header, Rumpf reassembliert).
- 🔶 **Meilenstein M3 erreicht (über eigenen Client):** Server-Seite gebaut — `TlsServerHandshake`
  (ServerHello/EE/Certificate/CertificateVerify-Signatur/Finished, Client-Finished-Prüfung),
  `ServerCertificate` (self-signed ECDSA P-256 via `CertificateRequest`), `QuicServerConnection`,
  `Http3ServerConnection`. Sample `H3Server` (UDP): unser `H3Get`-Client holt darüber Status 200 +
  HTML über echtes localhost-UDP; zusätzlich In-Process-Test (Client↔Server, beide from scratch).
  ✅ Interop-Bausteine: **X25519** (BouncyCastle, `IKeyExchange`) und **HelloRetryRequest** (Client +
  Server) implementiert. Client bietet X25519+P-256 an; Server wählt aus den Key Shares bzw. sendet HRR.
  Live-Beweis: gegen cloudflare-quic.com wird X25519 ausgehandelt. ⬜ Direkter Test mit `curl --http3`
  steht aus (lokales curl ist ein Schannel-Build ohne HTTP/3-Backend).

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
- 🔶 **Transport-Error-Matrix** (RFC 9000 §11/§20.1): Protokollverstöße der Gegenseite → CONNECTION_CLOSE
  mit korrektem Fehlercode statt Crash/still. Umgesetzt: FRAME_ENCODING_ERROR (Kodier-/Unbekannt-Fehler
  beim Frame-Parsen), STREAM_LIMIT_ERROR (Stream-Index jenseits des gewährten Limits), FLOW_CONTROL_ERROR
  und FINAL_SIZE_ERROR (aus `StreamReceiveBuffer` verdrahtet). Nebenbei **PATH_CHALLENGE/PATH_RESPONSE**
  (RFC 9000 §19.17/§19.18) ergänzt und beantwortet — nötig, damit „unbekanntes Frame = fatal" Cloudflare
  nicht bricht (live bestätigt). In-process getestet (u. a. STREAM_LIMIT_ERROR end-to-end). ⬜ verbleibende
  Codes (STREAM_STATE_ERROR, connection-level FLOW_CONTROL, TRANSPORT_PARAMETER_ERROR) + Parser-Fuzzer.
- Grease: reservierte Frame-/Stream-Typen der Gegenseite tolerieren.

### ⬜ Phase 9 — Performance & Nice-to-have (offenes Ende)
- Zero-Allocation-Pfad: `SocketAddress`-basierte Sende-/Empfangsschleife, Buffer-Pooling,
  `IBufferWriter<byte>`-Pipeline.
- UDP-Batching: mehrere Datagramme pro Syscall; GSO/GRO (Linux) hinter Abstraktion.
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
5. **Interop-Ziele:** cloudflare-quic.com, quic.nginx.org, www.google.com (Client-Seite);
   `curl --http3`, Firefox/Chrome (Server-Seite). Später ggf. quic-interop-runner-Testfälle
   manuell nachstellen.
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

**Stufe 1 — v1, Pflicht (reine BCL):** 🔶 (Kern steht, Signaturprüfung folgt mit Phase 2b)
- ✅ AEAD: AES-128-GCM (`AesGcm`); AES-256-GCM vorbereitet (`TrafficKeys` parametrisiert)
- ✅ Key Exchange: `secp256r1` (P-256) via `ECDiffieHellman` (`EcdheKeyExchange`)
- ⬜ Signaturen: RSA-PSS, ECDSA P-256/P-384 (für CertificateVerify — Phase 2b)
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

- **Kein** ChaCha20 / X25519 in v1 (AES-GCM + P-256 reichen für Interop mit allen relevanten
  Servern; Ausbau siehe Krypto-Roadmap).
- **Kein** 0-RTT, **kein** Server-Push, **kein** CUBIC/BBR, **keine** Multipath-Erweiterung in v1.
- QPACK zunächst ohne dynamische Tabelle (spec-konform und interop-fähig).
- Kein HTTP/1.1/2-Fallback, kein Alt-Svc-Handling — reines HTTP/3.

## Empfohlene Reihenfolge der ersten Schritte

1. ✅ Phase 0 + VarInt mit Tests (halber Tag).
2. ✅ RFC-9001-Appendix-A-Vektoren zum Laufen bringen (Initial Secrets, AEAD, Header Protection) —
   damit steht das ganze Krypto-Fundament nachweislich korrekt.
3. ✅ ClientHello bauen, Initial-Paket an cloudflare-quic.com senden, ServerHello zurückparsen —
   ab hier gibt es bei jedem Schritt echtes Server-Feedback statt Trockenübungen.

**Als Nächstes (Phase 2b):** Aus dem ECDHE-Shared-Secret + Transcript-Hash (ClientHello‖ServerHello)
die Handshake-Secrets ableiten (RFC 8446 §7.1) → Handshake-Pakete entschlüsseln
(EncryptedExtensions/Certificate/Finished). Danach ACK-Erzeugung + Verbindungs-State-Machine (Phase 3).

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
