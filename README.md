# HTTP/3 from Scratch

Ein HTTP/3-Stack (QUIC + TLS 1.3 + HTTP/3) in reinem C# auf .NET 10, direkt auf UDP-Sockets
aufsetzend – **ohne große Abhängigkeiten**, nur die .NET Base Class Library.

Der Implementierungsplan mit allen Phasen, Meilensteinen und der Krypto-Roadmap steht in
[PLAN.md](PLAN.md); die Interop-Nachweise (8 fremde QUIC-Stacks) und wie man sie **jederzeit
wiederholt** in [INTEROP.md](INTEROP.md) (`dotnet run --project samples/H3Get -- --interop`).

## Status

| Phase | Inhalt | Status |
|-------|--------|--------|
| 0 | Setup, VarInt, Buffer-Reader/Writer, Testgerüst | ✅ fertig |
| 1 | Initial-Krypto (HKDF, Packet/Header Protection, Retry) — RFC 9001 App. A byte-genau | ✅ fertig |
| 1b | QUIC-Paketformate (Long/Short Header, Connection ID, Paketnummern) — RFC 9000 §17 | ✅ fertig |
| 1c | QUIC-Frames (PADDING, PING, ACK, CRYPTO, STREAM, CONNECTION_CLOSE, …) — RFC 9000 §19 | ✅ fertig |
| 2 | TLS-1.3-Handshake: ClientHello, ServerHello, ECDHE (P-256), Transport-Parameter | ✅ fertig |
| 2b | TLS-Key-Schedule (RFC 8448 verifiziert) → Handshake-Pakete live entschlüsselt | ✅ fertig |
| 3a | Eigenen Finished senden, ACKs, 1-RTT-Keys — **Handshake vollständig abgeschlossen** | ✅ fertig |
| 3b | Wiederverwendbare `QuicClientConnection` + `TlsClientHandshake`-Engine | ✅ fertig |
| **M1** | **Voller QUIC/TLS-1.3-Handshake gegen cloudflare-quic.com — HANDSHAKE_DONE empfangen** | ✅ **erreicht** |
| 4 | Streams & Flow Control — Server-HTTP/3-Streams reassembliert | ✅ fertig |
| 6 | QPACK (statische Tabelle + Huffman + Literale) — RFC-Vektoren verifiziert | ✅ fertig |
| 7 | HTTP/3 (Control-/QPACK-Streams, SETTINGS, HEADERS/DATA) | ✅ fertig |
| **M2** | **Echtes `GET https://cloudflare-quic.com/` — Status 200 + 126 KB HTML** | ✅ **erreicht** |
| 4-FC | Empfangsseitige Flow-Control-Updates (`MAX_STREAM_DATA`/`MAX_DATA`) | ✅ fertig |
| 5 | Loss Recovery (RFC 9002): RTT, Loss Detection, PTO, NewReno, Retransmission | ✅ fertig |
| 8-S | HTTP/3-**Server** (TLS-Server-Handshake, self-signed Cert, QUIC/HTTP-3-Server) | ✅ fertig |
| **M3** | **Eigener Server: `H3Get`-Client holt Status 200 + HTML über echtes localhost-UDP** | ✅ **erreicht** |
| 8 | Robustheit: VN, Retry, Close/Draining, Idle/Keep-Alive, Key-Lifecycle & Key Update, 0-RTT + Resumption, CID-Rotation, Stateless Reset, Migration, RESET_STREAM/STOP_SENDING, PQ-Hybrid, ML-DSA-Zertifikate | ✅ im Kern fertig |
| 7+ | **RFC-9114-Feature-Audit**: Request-Bodies, Cancellation, Frame-Zustandsmaschine + H3-Fehlercodes, GOAWAY, Trailer/1xx, MAX_FIELD_SECTION_SIZE, Malformed-Validierung | ✅ **komplett** |
| 9218 | **Priorities**: priority-Header + PRIORITY_UPDATE, §10-Scheduler (Urgency/inkrementell) | ✅ fertig |
| 9220 | **WebSockets über HTTP/3**: Extended CONNECT (RFC 8441) + Tunnel + RFC-6455-Framing (aus Hermod wiederverwendet) | ✅ fertig |
| 9297/9221 | **HTTP-Datagramme** über QUIC-DATAGRAM-Frames | ✅ fertig |
| webtrans | **WebTransport über HTTP/3** (draft-13): Sessions, uni/bidi-Streams, Datagramme, Flow-Control-Capsules, Protokoll-Aushandlung (`WT-Available-Protocols`/`WT-Protocol`) | ✅ fertig |
| reset-at | **RESET_STREAM_AT** (draft-ietf-quic-reliable-stream-reset): Stream-Reset mit garantierter Teilzustellung (`reset_stream_at`-TP + Frame 0x24) | ✅ fertig |
| async | **async API**: `Http3Client`/`Http3Server` — Task-Fassaden mit eigenem UDP-Socket + Hintergrund-Pump (`ConnectAsync`/`GetAsync`/`SendAsync`, `Http3RequestException`, CID-Demux inkl. Migration) | ✅ fertig |
| curl | **`curl --http3`-Interop (Server-Seite)**: ngtcp2/LibreSSL (Windows-curl 8.21) **und** OpenSSL-QUIC (WSL/Debian-curl 8.14) — GET/POST/300 KB/103+Trailer | ✅ fertig |
| 8+ | **Transport-Error-Matrix komplett**: connection-level FLOW_CONTROL_ERROR, TRANSPORT_PARAMETER_ERROR (§7.3-Authentifizierung + §7.4/§18.2-Wertebereiche), §10.2.3-Close-Zustellung, Parser-Fuzzer | ✅ fertig |
| 9 | **Performance**: Zero-Alloc-Hot-Paths (`ByteQueue`, 300-KB-Download 51→7 MiB), UDP-Batching (GSO via `UdpBatchSender`), Window-Auto-Tuning (`ReceiveWindowTuner`, BDP) | ✅ fertig |
| interop | **Client-Interop gegen 8 fremde QUIC-Stacks**: quiche, nginx, Google, mvfst, lsquic, msquic, quic-go, Akamai — je 2xx/3xx mit voller Cert-Prüfung | ✅ fertig |

### X25519 & HelloRetryRequest (Interop)

- `X25519KeyExchange` (BouncyCastle, hinter `IKeyExchange` gekapselt — einzige externe Krypto-Dep);
  Client bietet X25519 + P-256 an, Server wählt aus den Key Shares
- **HelloRetryRequest** (RFC 8446 §4.1.4) auf Client- **und** Server-Seite, inkl. der synthetischen
  `message_hash`-Transcript-Behandlung — in-process getestet (Client bietet nur P-256, Server verlangt
  X25519 → HRR → Abschluss mit X25519)
- **Live:** gegen `cloudflare-quic.com` wird **X25519** ausgehandelt (`Handshake abgeschlossen (Gruppe X25519)`)
- **Client-Interop-Matrix (live, volle Cert-Prüfung ohne `-k`):** der Client holt Status 2xx/3xx von **8
  unabhängigen QUIC-Stacks** — quiche (Cloudflare), nginx, Google, mvfst (Meta), lsquic (LiteSpeed),
  **msquic** (Microsoft, `outlook.office.com` — P-256 + AES-256 + RSA), quic-go (Caddy) und Akamai
  (AES-256). Deckt beide KEX (X25519 + P-256), beide Suiten (AES-128/256-GCM) und beide Cert-Typen
  (ECDSA + RSA-PSS) live ab. Ganze Tabelle + Ein-Befehl-Wiederholung: **[INTEROP.md](INTEROP.md)**
  (`dotnet run --project samples/H3Get -- --interop`).
- **X448** (RFC 7748, Curve448, Named Group 0x001e): Schlüsselaustausch-Primitiv aus BouncyCastle
  (`X448KeyExchange`, wie X25519 gekapselt), 56-Byte-Key/-Secret. RFC 7748 §5.2 byte-genau; die Named Groups
  sind durch die ganze API durchgereicht (`keyExchangeGroups`/`preferredGroups`). Live über UDP:
  `H3Server --x448` + `H3Get --x448 -k` → Gruppe X448, Status 200
- **X25519MLKEM768** (Post-Quantum-Hybrid, Named Group 0x11EC, draft-ietf-tls-ecdhe-mlkem): kombiniert
  **ML-KEM-768 aus der BCL** (`MLKem`, .NET 10 nativ) mit X25519 (BouncyCastle). Ein KEM ist asymmetrisch,
  daher hat `IKeyExchange` eine `Encapsulate`-Methode (Server encapsuliert, Client decapsuliert). Shares/Secret:
  ek(1184)‖x25519 / ct(1088)‖x25519 / ss_mlkem‖ss_x25519 — ML-KEM zuerst. **Byte-genau interop live gegen
  cloudflare-quic.com** (`H3Get --mlkem` → Gruppe X25519MlKem768, volle Kette, Status 200, 126 KB)
- **Ed25519** (RFC 8032, `SignatureScheme` 0x0807): Signaturprimitiv aus BouncyCastle (`Ed25519Signature`,
  wie X25519 gekapselt) — Client verifiziert die CertificateVerify-Signatur (PureEdDSA, kein Vor-Hash),
  `ServerCertificate` erzeugt bei Bedarf ein selbstsigniertes Ed25519-Zertifikat. RFC 8032 §7.1 byte-genau;
  live über UDP: `H3Server --ed25519` + `H3Get -k` → Signatur geprüft, Status 200
- **Ed448** (RFC 8032, `SignatureScheme` 0x0808, edwards448/SHAKE256): analog aus BouncyCastle
  (`Ed448Signature`), PureEdDSA mit leerem Kontext, 57-Byte-Key / 114-Byte-Signatur; `ServerCertificate`
  erzeugt bei Bedarf ein Ed448-Zertifikat. RFC 8032 §7.4 byte-genau; live über UDP: `H3Server --ed448` +
  `H3Get -k` → Signatur geprüft, Status 200
- **ML-DSA** (FIPS 204, draft-ietf-tls-mldsa, `SignatureScheme` mldsa44/65/87 = 0x0904–0x0906):
  Post-Quantum-Signaturen, komplett **BCL-nativ** (.NET 10 `MLDsa` + `CertificateRequest`) — pure
  Signatur ohne Vor-Hash, FIPS-204-Kontext leer; der Client prüft zusätzlich, dass die
  Parameterstärke des Zertifikatsschlüssels (id-ML-DSA-44/65/87) zum Scheme passt.
  `ServerCertificate.CreateSelfSignedMLDsa()`. Live über UDP: `H3Server --mldsa` + `H3Get -k` →
  Status 200 — und **voll post-quantum** mit `--mldsa --mlkem` (X25519MLKEM768-KEX + ML-DSA-65-Signatur)

### HTTP/3-Server (M3)

- `ServerCertificate` — self-signed ECDSA-P-256 via `CertificateRequest` (für `curl -k` / Tests)
- `TlsServerHandshake` — ServerHello/EncryptedExtensions/Certificate/**CertificateVerify (signiert)**/
  Finished, prüft den Client-Finished. In-process gegen den Client-Handshake verifiziert (matching secrets)
- `QuicServerConnection` — Server-Rolle (Initial-Keys aus der Client-DCID, HANDSHAKE_DONE),
  `Http3ServerConnection` — nimmt Requests entgegen, ruft einen Handler, sendet HEADERS + DATA
- Client und Server teilen sich die Transport-Logik über die Basisklasse `QuicEndpoint`; die beiden
  Verbindungsklassen sind schlanke Subklassen mit Rollen-Hooks (Schlüsselrichtung/Stream-Perspektive über `IsServer`)
- **M3 live:** `dotnet run --project samples/H3Server` + `dotnet run --project samples/H3Get -- localhost / --port=4433 -k`
  → Status 200 + selbstgebaute HTML-Seite über echtes UDP (beide Enden from scratch)
- **`curl --http3`-Interop:** die Server-Seite besteht gegen zwei unabhängige fremde HTTP/3-Stacks —
  das offizielle Windows-curl 8.21 (**ngtcp2 + nghttp3 + LibreSSL**) und das Debian-curl 8.14 unter
  **WSL** (**OpenSSL-3.5-QUIC** + nghttp3, über die WSL2-NAT-Grenze): Handshake, `GET /` (200),
  `POST /echo` (byte-genaues Echo), `GET /big` (300 000 B), `GET /hints` (103 Early Hints + finale
  200 + Trailer), saubere Closes. Beispiel: `curl --http3-only -k https://127.0.0.1:4433/`

### Zertifikatsprüfung (Client)

- **CertificateVerify-Signatur** (RFC 8446 §4.4.3) über den Transcript-Hash mit dem öffentlichen
  Schlüssel des Leaf-Zertifikats — **immer** geprüft (ECDSA P-256/P-384, RSA-PSS). Das ist die
  eigentliche kryptografische MITM-Abwehr: sie bindet das präsentierte Zertifikat an genau diesen
  Handshake.
- **Vertrauens-Policy** getrennt davon, per `CertificateValidationOptions`: Kettenaufbau bis zu einer
  vertrauenswürdigen Wurzel (`X509Chain`), Hostname (`X509Certificate2.MatchesHostname`) und
  Gültigkeitszeitraum. `Default` = volle Prüfung gegen die System-Roots; `Insecure` = wie `curl -k`
  (nur Signatur); `CustomTrustRoots` = gezielt einem Testzertifikat vertrauen.
- **Live:** GET gegen `cloudflare-quic.com` läuft mit **voller** Kettenprüfung durch
  (`CN=cloudflare-quic.com`, Kette bis zu einer Windows-System-Root, Hostname-Match). Der lokale
  self-signed H3Server wird ohne `-k` korrekt **abgelehnt**, mit `-k` akzeptiert.

### Flow Control & Loss Recovery (Phase 4/5)

- **Flow Control (Empfang):** `QuicClientConnection` führt die Fenster nach und sendet
  `MAX_STREAM_DATA`/`MAX_DATA`, sobald der Kredit unter das halbe Fenster fällt — mit `--small`
  lädt das Sample die 126-KB-Seite auch durch ein 48-KB-Verbindungsfenster.
- **Loss Recovery (RFC 9002):** `RttEstimator`, `NewRenoCongestionControl`, `LossRecovery`
  (Sent-Packet-Tracking, Paket-/Zeitschwelle, PTO). Verlorene CRYPTO/STREAM-Frames werden neu
  gesendet. `dotnet run --project samples/H3Get -- --loss=10` übersteht den Verlust: Handshake +
  GET kommen trotz ~17 verworfener Datagramme durch.
- **ECN (RFC 9000 §13.4 / RFC 9002 §7.3):** Der Empfänger zählt die ECN-Codepoints (ECT0/ECT1/CE) je
  Packet-Number-Space und meldet sie im ACK-Frame (Typ 0x03); der Sender behandelt einen gestiegenen
  CE-Zähler wie einen Verlust und halbiert das Congestion Window (einmal pro Recovery-Periode). Der
  Codepoint kommt über `ProcessDatagram(dg, ecn)` herein. In-process verifiziert (Zählung/Meldung,
  CE-Reaktion, End-to-End cwnd-Rückgang). Das eigentliche IP-Marking (ECT setzen/CE lesen) übersteigt
  BCL-UDP-Sockets (v. a. Windows) — reine Transportschicht, die Protokoll-Logik ist vollständig.
- **cwnd-Enforcement & Pacing (RFC 9002 §7/§7.7):** Neue Stream-Daten werden durch
  `min(cwnd − bytes_in_flight, Pacing-Budget)` begrenzt; der `Pacer` (Token-Bucket, Rate
  `1.25·cwnd/smoothed_rtt`, Burst-Cap ≈ Initial Window) verteilt sie zeitlich, reine ACKs und
  PTO-Probes bleiben ausgenommen. Der 1-RTT-Sendepfad emittiert mehrere **MTU-große** Pakete pro
  Aufruf. Ein 150-KB-In-Process-Transfer belegt byte-genaue, MTU-konforme Übertragung über den
  gepacten Pfad.
- **Persistent Congestion (RFC 9002 §7.6):** Bei einer Blackout-Phase (zwei ack-eliciting Pakete
  verloren, nichts dazwischen bestätigt, Abstand > PC-Dauer `≈ PTO·3`) kollabiert das Fenster auf
  `kMinimumWindow` und Slow Start startet neu — greift nur nach der ersten RTT-Stichprobe.
- **Idle Timeout (RFC 9000 §10.1):** `IdleTimeout` handelt `min(lokal, peer)` aus (0 = deaktiviert),
  hebt effektiv auf mind. `3·PTO` an und startet den Timer bei erfolgreichem Empfang bzw. beim Senden
  eines ack-eliciting Pakets neu. Läuft er ab, wird die Verbindung still geschlossen. Der `H3Server`
  reapt inaktive Verbindungen — `dotnet run --project samples/H3Server -- 4433 --idle=3000` schließt
  eine Verbindung ~3 s nach dem letzten Paket (im Log: „nach Idle-Timeout geschlossen").
- **Keep-Alive via PING (RFC 9000 §10.1.2):** Ist `KeepAliveInterval` gesetzt, plant die Verbindung nach
  entsprechender Inaktivität ein ack-eliciting PING ein, das den Idle-Timeout auf beiden Seiten zurücksetzt.
  **Live:** `H3Get … --hold=6` gegen `H3Server … --idle=3000` — die Verbindung bleibt 6 s untätig offen,
  wo sie ohne Keep-Alive nach 3 s gereapt würde.

### Version Negotiation & Retry (RFC 9000 §6/§8.1)

- **Version Negotiation:** Der Server beantwortet eine nicht unterstützte Version mit einem
  `VersionNegotiationPacket` (Versionsfeld 0, gelistete Versionen, DCID/SCID vertauscht). Anti-Amplification
  (§6.1/§14.1): kein VN auf Datagramme < 1200 B. Als GREASE (§6.3) liegt eine reservierte Version im Muster
  `0x?a?a?a?a` bei, um Client-Robustheit zu prüfen und Ossifizierung vorzubeugen. Der Client erkennt VN,
  wendet die §6.2-Verwerfungsregeln an, ignoriert die reservierte Version und meldet sonst
  `VersionNegotiationReceived` + `OfferedVersions`.
- **Retry / Adressvalidierung:** Mit `--retry` sendet der `H3Server` auf das erste Initial ein
  `RetryPacket` mit Token und 16-Byte Integrity Tag (RFC 9001 §5.8). Der Client prüft den Tag gegen
  seine ursprüngliche DCID, leitet die Initial-Schlüssel aus der Retry-SCID **neu** ab (RFC 9001 §5.2),
  spiegelt das Token im nächsten Initial und schließt den Handshake ab. **Live:**
  `dotnet run --project samples/H3Server -- 4433 --retry` + `H3Get … -k` → „Handshake abgeschlossen …
  nach Retry (Adressvalidierung)" + Status 200.

### Connection Close & Draining (RFC 9000 §10.2)

- `Close(TransportError, reason)` sendet ein CONNECTION_CLOSE und versetzt die Verbindung in den
  **Closing**-Zustand (nur noch CONNECTION_CLOSE, auf jedes eingehende Paket erneut). Der Empfang eines
  CONNECTION_CLOSE führt in den **Draining**-Zustand (sendet nichts mehr, `PeerCloseFrame` gemerkt); nach
  `3·PTO` folgt **Closed**. Zustände über `IsClosing`/`IsDraining`/`IsClosed` sichtbar.
- **Live:** `H3Get` schließt nach dem GET anständig ab („CONNECTION_CLOSE, NO_ERROR"); der `H3Server`
  loggt „Peer … schloss die Verbindung" und sortiert die drainende Verbindung aus.

### Schlüssel-Lebenszyklus (RFC 9001 §4.9)

- **Verwerfen nach dem Handshake:** Initial-Keys werden verworfen, sobald der Client ein Handshake-Paket
  sendet bzw. der Server eines verarbeitet (§4.9.1); Handshake-Keys, sobald der Handshake bestätigt ist (§4.9.2).
  `DiscardKeys` räumt Keys, ausstehende CRYPTO/Retransmits und den Loss-Recovery-Space (RFC 9002 §6.4). Behebt
  einen Bug, bei dem ein PTO nach dem Handshake fälschlich den Initial-Space sondierte und den ClientHello als
  1200-Byte-Initial erneut sendete.
- **Handshake-Bestätigung (§4.1.2):** Der Server bestätigt beim Abschluss; der Client bei HANDSHAKE_DONE **oder**
  – zusätzlich (RFC-legitim) – sobald eines seiner **1-RTT-Pakete quittiert** wird. So werden die Handshake-Keys
  auch dann (früher) verworfen, wenn HANDSHAKE_DONE verloren geht – in-process verifiziert (Bestätigung allein per
  1-RTT-ACK bei unterdrücktem HANDSHAKE_DONE).
- **Kein Reordering-Fenster für Handshake-Keys (§4.9.2):** Die Handshake-Keys werden bei der Bestätigung **sofort**
  verworfen – anders als 0-RTT-Keys, für die §4.9.3 dem Server ein kurzes Aufbewahren (~3×PTO) gegen Reordering
  ausdrücklich erlaubt. Diese Asymmetrie ist gewollt: nach der beidseitig fertigen Bestätigung trüge ein spät
  reordertes Handshake-Paket nur schon Bekanntes, und längeres Vorhalten vergrößerte nur das Angriffsfenster.
  (Das „kurz behalten" voriger Read-Keys betrifft ausschließlich das 1-RTT Key Update nach §6.)
- **0-RTT-Keys des Clients (§4.9.3):** Der Client verwirft seinen 0-RTT-Schlüsselsatz, sobald die 1-RTT-Keys stehen
  – er sendet danach keine 0-RTT-Pakete mehr und empfängt selbst nie welche. Dafür gibt es **kein** Reordering-
  Fenster (anders als beim Server): der Client hat keinen 0-RTT-Read-Pfad, und verlorene 0-RTT-Daten laufen über
  1-RTT nach – die Keys haben „no use after that moment".
- **0-RTT-Read-Keys des Servers (§4.9.3):** Der Server behält sie nach dem **ersten empfangenen 1-RTT-Paket** noch
  kurz (damit reorderte 0-RTT-Pakete ohne 1-RTT-Neuübertragung entschlüsselbar bleiben) und verwirft sie dann
  „within a short time" — RECOMMENDED **3×PTO**, rein zeitgesteuert (auch ohne weiteren Verkehr). **Früher**, sobald
  die Paketnummern ab 0 lückenlos sind: dann sind nachweislich alle 0-RTT-Pakete da („keeping track of missing
  packet numbers"), und die Keys werden sofort verworfen, statt die Frist abzuwarten. Endet die Verbindung vorher,
  gibt `Dispose()` die 0-RTT-Read-Keys frei (neben allen übrigen Schlüsseln).

### Key Update (RFC 9001 §6)

- `TrafficKeys.Next` leitet die nächste Generation ab (`secret_<n+1> = HKDF-Expand-Label(secret_<n>,
  "quic ku", …)` → neuer Key/IV, **HP-Key unverändert**). `PacketProtection.RemoveHeaderProtection`
  trennt Header- von Paketschutz, damit das **Key-Phase-Bit** vor der Schlüsselwahl gelesen werden kann.
- `InitiateKeyUpdate()` rotiert die Send-Keys und kippt die Phase; ein empfangenes gekipptes Bit rotiert
  Read- (und ggf. Send-)Keys, vorige Read-Keys bleiben kurz für umsortierte Pakete erhalten.
- **Live:** `dotnet run --project samples/H3Get -- --key-update` holt die Seite, rotiert die Schlüssel und
  wiederholt das GET **unter den neuen Schlüsseln** — gegen `cloudflare-quic.com` beide Male Status 200.

### Session Resumption / PSK (RFC 8446 §2.2/§4.6.1) + 0-RTT (RFC 9001 §4)

- Der Server stellt nach dem Handshake ein **NewSessionTicket** aus (stateful `ServerResumptionCache`);
  der Client leitet daraus die Resumption-PSK ab (`resumption_master_secret` → `HKDF-Expand-Label(…,
  "resumption", nonce)`) und speichert sie als `ResumptionTicket`.
- Die Wiederaufnahme sendet `pre_shared_key` (als **letzte** Extension) mit **Binder** — `HMAC(finished_key(
  binder_key), Transcript-Hash(ClientHello bis vor die Binder-Liste))`, die klassische Trunkierungsgrenze aus
  RFC 8446 §4.2.11.2 — plus `psk_key_exchange_modes` (das wird **immer** gesendet, sonst stellt der Server
  keine Tickets aus). Der Server prüft den Binder und resümiert **ohne Zertifikat/CertificateVerify**.
- **Live Resumption:** `H3Get --resume` → erst ein GET, dann eine zweite Verbindung per PSK. Gegen
  `cloudflare-quic.com` liefert Cloudflare 2 echte Tickets, akzeptiert unseren Binder byte-genau (**„PSK
  akzeptiert, kein Zertifikat"**) und beantwortet das zweite GET mit Status 200; ebenso gegen `H3Server` über UDP.
- **0-RTT (Early Data):** erlaubt das Ticket 0-RTT, sendet der Client die `early_data`-Extension und leitet das
  `client_early_traffic_secret` ab. Die HTTP/3-Anfrage wird **vor** dem Handshake-Abschluss als **0-RTT-Paket**
  (Long Header 0x01, eigener Schlüsselsatz im Application-PN-Space) gesendet; der Server bestätigt early_data in
  den EncryptedExtensions und verarbeitet die Anfrage sofort. **Live:** `H3Get --zerortt` gegen
  `cloudflare-quic.com` → **„0-RTT AKZEPTIERT"**, 126 KB, Status 200 (kein Round-Trip bis zum Request); ebenso
  gegen `H3Server` über UDP.
- **0-RTT-Ablehnung → 1-RTT-Retry** (RFC 9001 §4.6.2): lehnt der Server early_data ab, greift dank des geteilten
  Application-PN-Space schon die normale Loss Recovery; zusätzlich verschiebt der Client die 0-RTT-Frames bei
  erkannter Ablehnung **proaktiv** in die 1-RTT-Retransmit-Queue (ohne PTO-Wartezeit, ohne Doppelsenden). Die
  Anfrage kommt so auch bei Ablehnung durch — in-process verifiziert (Server lehnt ab ⇒ Status 200 über 1-RTT).
  Auch der **Handshake-Key-Discard** bleibt auf diesem Pfad korrekt: die Bestätigung per 1-RTT-ACK (§4.1.2) zählt
  nur echte 1-RTT-Pakete (nie ein 0-RTT-Paket, obwohl beide denselben PN-Space teilen), sodass ein 0-RTT-ACK den
  Handshake nie zu früh bestätigt — verifiziert (0-RTT abgelehnt + HANDSHAKE_DONE unterdrückt ⇒ Bestätigung nur
  über den 1-RTT-ACK, danach Handshake-Keys weg).

### Connection-ID-Rotation (RFC 9000 §5.1)

- `ConnectionIdManager` verwaltet die von uns ausgegebenen (Peer → DCID) und die vom Peer angebotenen
  (wir → DCID) Connection IDs samt Sequenznummern. `IssueConnectionId()` sendet NEW_CONNECTION_ID
  (respektiert `active_connection_id_limit`); `RotateDestinationConnectionId()` wechselt die DCID und zieht
  die alte per RETIRE_CONNECTION_ID zurück. „Retire Prior To" und eingehende RETIRE werden behandelt;
  Pakete an eine nicht (mehr) ausgegebene lokale CID werden verworfen.
- **Live über UDP:** `H3Server` bietet nach dem Handshake eine Reserve-CID an; `H3Get … --rotate-cid`
  stellt seine DCID darauf um und wiederholt das GET **unter der neuen Connection ID** (Status 200).

### Stateless Reset (RFC 9000 §10.3)

- **Empfang:** Stateless-Reset-Tokens des Peers (aus NEW_CONNECTION_ID + `stateless_reset_token`-TP) werden
  gespeichert. Ein nicht verarbeitbares Short-Header-Datagramm, dessen **letzte 16 Bytes** einem bekannten
  Token entsprechen (konstantzeitig), wird als Stateless Reset erkannt und beendet die Verbindung
  (`StatelessResetReceived` → Draining).
- **Senden:** Der Server leitet seine Tokens aus der CID ab — `StatelessResetTokenGenerator` =
  `HMAC-SHA256(geheim, CID)[0..16]` (§10.3.1) —, sodass sie nach Zustandsverlust neu berechenbar bleiben.
  Der Demux (`H3Server`) beantwortet ein 1-RTT-Paket zu **unbekannter** DCID mit `StatelessReset.BuildResponse`:
  Token aus der DCID rechnen, einen Reset **kleiner** als das auslösende Paket bauen (Loop-Vermeidung §10.3.3),
  nur auf Short-Header ab Mindestgröße. In-process end-to-end getestet (zustandsloser Responder mit geteiltem
  Geheimnis → Reset, den der Client erkennt).
- **Persistiertes Geheimnis:** Der `H3Server` speichert das Geheimnis in einer Datei (`--secret-file=`, Standard
  neben der Exe) und lädt es beim Start — so bleibt es über **Neustarts** gleich (verifiziert: identische Bytes,
  Startmeldung „geladen — überlebt Neustarts"), womit ein neu gestarteter Server für vor dem Neustart aufgebaute
  Verbindungen gültige, vom Client erkennbare Resets senden kann. Der Demux öffnet neue Verbindungen nur noch auf
  echte **Initial**-Pakete; Short-Header zu unbekannter CID ⇒ Reset, andere Long-Header ⇒ verworfen.

### Transport-Error-Matrix (RFC 9000 §11)

- Protokollverstöße der Gegenseite werden mit einem CONNECTION_CLOSE des passenden Fehlercodes beantwortet,
  statt still ignoriert zu werden oder zu crashen: **FRAME_ENCODING_ERROR** (kaputtes/unbekanntes Frame),
  **STREAM_LIMIT_ERROR** (Stream jenseits des gewährten Limits), **FLOW_CONTROL_ERROR** und
  **FINAL_SIZE_ERROR** (aus dem `StreamReceiveBuffer` verdrahtet). Nach dem ersten Verstoß werden keine
  weiteren Frames des Pakets mehr verarbeitet.
- Zugleich sind **PATH_CHALLENGE/PATH_RESPONSE** (RFC 9000 §19.17/§19.18) ergänzt und werden beantwortet —
  damit deckt der Parser alle v1-Frames ab und „unbekanntes Frame = fatal" bricht echte Server nicht
  (gegen `cloudflare-quic.com` live bestätigt). End-to-end getestet (u. a. STREAM_LIMIT_ERROR).

### Connection Migration (RFC 9000 §8.2/§9)

- **Pfadvalidierung:** `InitiatePathValidation()` sendet ein PATH_CHALLENGE mit 8 Zufallsbytes; ein
  passendes PATH_RESPONSE setzt `PathValidated` (Frist 3·PTO). PATH_CHALLENGE wird beantwortet. Über
  `OwnsConnectionId` lassen sich Verbindungen an der Connection ID (statt der Adresse) erkennen.
- **Live über UDP:** Der `H3Server` demultiplext über die Connection ID; `H3Get … --migrate` wechselt den
  lokalen UDP-Port und holt ein zweites GET — der Server erkennt die Migration (Log: „Connection Migration:
  … → …"), validiert den neuen Pfad und beantwortet das GET **über den neuen Pfad** (Status 200). Die
  Verbindung überlebt den Adresswechsel. In-process getestet (Client-/Server-initiiert + Ablauf-Timeout).

### Anti-Amplification-Limit (RFC 9000 §8.1)

- Vor der Adressvalidierung sendet der **Server** höchstens **3× so viele Bytes, wie er empfangen hat** —
  Schutz gegen Amplification via gefälschter Absenderadresse. Reicht das Budget nicht, bleibt die CRYPTO
  persistent gepuffert und geht raus, sobald mehr empfangen wurde. Validiert ist die Adresse beim ersten
  entschlüsselten **Handshake-Paket** (der Peer besitzt unsere Handshake-Schlüssel) oder bei einem gültigen
  **Retry-Token**; der Client limitiert sich per Konstruktion nicht. Getestet über die Invariante
  `gesendet ≤ 3×empfangen`; live läuft der eigene Server unter dem Limit ans Ziel.

### HTTP/3 (Phase 7, RFC 9114 — `Http3`)

- `Http3Frames` (DATA/HEADERS/SETTINGS, inkrementelles Parsen), `Http3Request`/`Http3Response`
- `Http3ClientConnection` über `QuicClientConnection`: öffnet Control-Stream (+ SETTINGS) und
  QPACK-Encoder/Decoder-Streams, sendet Requests als QPACK-kodiertes HEADERS-Frame auf einem
  bidirektionalen Stream, reassembliert die Antwort (HEADERS → QPACK-Decode, DATA → Rumpf)
- **Request-Bodies (RFC 9114 §4.1):** `Http3Request.Body`/`Http3Request.Post(...)` — der Rumpf folgt
  als DATA-Frame auf das HEADERS-Frame (automatischer `content-length`, §4.1.2); der Server sammelt
  DATA-Frames ein und beantwortet die Nachricht erst, wenn sie vollständig ist (FIN). Getestet per
  POST-Echo + 120-KB-Upload (SHA-256-verifiziert, erstmals der Client-Sendepfad unter Last);
  **live:** `H3Get --post=<Text>` — Echo gegen den eigenen `H3Server` (`POST /echo`) über UDP und
  POST gegen `cloudflare-quic.com` (Status 200)
- **Request-Cancellation (RFC 9114 §4.1.1) + RESET_STREAM/STOP_SENDING (RFC 9000 §19.4/§19.5):**
  `CancelRequest` bricht Sende- und Leseseite mit `H3_REQUEST_CANCELLED` ab; die QUIC-Schicht liefert
  beide Frames zuverlässig (Loss Recovery), validiert Final Size (§4.5) und Stream-Zustände
  (STREAM_STATE_ERROR) und beantwortet STOP_SENDING automatisch mit RESET_STREAM samt kopiertem
  Fehlercode (§3.5 MUST); der Server erkennt Client-Abbrüche (H3_REQUEST_REJECTED/CANCELLED).
  H3-Fehlercodes (§8.1) als `Http3Error`. **Live:** `H3Get --cancel` gegen `cloudflare-quic.com` —
  Abbruch mitten im Download, Cloudflare resettet mit `0x10c`, ein zweites GET über **dieselbe**
  Verbindung liefert Status 200
- **Frame-/Stream-Zustandsmaschine (RFC 9114 §4.1/§6.2/§7.2):** Protokollverstöße der Gegenseite
  werden mit CONNECTION_CLOSE **Typ 0x1d** und dem korrekten H3-Fehlercode beantwortet —
  H3_MISSING_SETTINGS (erstes Control-Frame ≠ SETTINGS), H3_FRAME_UNEXPECTED (zweites SETTINGS,
  DATA vor HEADERS, Frames nach Trailern, reservierte HTTP/2-Typen, PUSH_PROMISE vom Client, …),
  H3_STREAM_CREATION_ERROR (doppelte kritische Streams, Client-Push-Stream), H3_CLOSED_CRITICAL_STREAM
  (Control-/QPACK-Stream endet), H3_SETTINGS_ERROR (reservierte/doppelte Setting-IDs), H3_FRAME_ERROR
  (Layout-Verstöße, abgeschnittenes letztes Frame), H3_ID_ERROR (Push ohne MAX_PUSH_ID, GOAWAY mit
  falscher ID). Grease-Frames/-Settings werden toleriert und selbst gesendet (§7.2.4.1 SHOULD);
  14 Tests mit vorsätzlich „bösen" Roh-QUIC-Peers in beide Richtungen, Interop live unverändert
- **WebSockets über HTTP/3 (RFC 9220 / RFC 8441 / RFC 6455):** Extended CONNECT mit
  `:protocol`-Pseudo-Header, gated per `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08); nach der
  2xx-Annahme wird der Request-Stream zum Byte-Tunnel (`Http3Tunnel`, Bytes in DATA-Frames per
  RFC 9114 §4.4; FIN ≙ TCP-Close, Reset ≙ `H3_REQUEST_CANCELLED`). Das **RFC-6455-Framing ist aus
  Hermods HTTP/2-WebSocket wiederverwendet** (byte-identische Kopien, nur der Namespace getauscht —
  es ist transport-agnostisch gegen das 2-Methoden-Tunnel-Interface geschrieben, inkl. Masking,
  UTF-8-Validierung, permessage-deflate, Close-Handshake). Unbekanntes `:protocol` ⇒ 501.
  **Live über UDP:** `H3Get --websocket` — CONNECT 200 → Text-Echo → Close-Handshake
- **WebTransport über HTTP/3 (draft-ietf-webtrans-http3-13, kompletter Draft inkl. Flow Control):**
  Session-Aufbau via Extended CONNECT (`:protocol=webtransport`, gated über SETTINGS_WT_MAX_SESSIONS +
  Datagramme; 404 für unbekannte Ressourcen, H3_REQUEST_REJECTED über dem Session-Limit); uni-Streams
  (Typ 0x54) und bidi-Streams (WT_STREAM 0x41), beide Seiten öffnend/empfangend; WebTransport-Datagramme;
  Flow Control über das Capsule-Protokoll (WT_MAX_STREAMS/WT_MAX_DATA/WT_*_BLOCKED); Session-Ende via
  WT_CLOSE_SESSION-Capsule (Streams mit WT_SESSION_GONE abgebrochen); App-Fehlercode-Remapping (§4.3);
  ALPN-artige Protokoll-Aushandlung (§3.3: Client bietet per `WT-Available-Protocols` — Structured-
  Fields-List aus Strings, RFC 9651 — an, der Server wählt per `WT-Protocol` genau eines; ungültige
  Werttypen ⇒ ganzes Feld ignoriert, Wahl außerhalb der Liste beidseitig verworfen).
  API: `ConnectWebTransport(…, availableProtocols:)`/`webTransportHandler`+`webTransportProtocolSelector`,
  `WebTransportSession` (OpenUni/Bidi, Accept*, SendDatagram, Close, `NegotiatedProtocol`).
  **Live über UDP:** `H3Get --webtransport` — Session, Datagramm-Echo, uni-/bidi-Stream (Echo),
  sauberes Ende, WT-Protocol `echo-v2` aus drei Angeboten ausgehandelt
- **RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset):** Stream-Reset mit garantierter
  Teilzustellung — der Grund, warum ein Empfänger den kritischen Stream-Präfix (z. B. den
  WebTransport-Stream-Kopf) trotz Abbruch sieht. Transport-Parameter `reset_stream_at` (0x1d, leerer
  Wert, Standard aktiv; nicht-leer ⇒ TRANSPORT_PARAMETER_ERROR) und Frame RESET_STREAM_AT (0x24 =
  RESET_STREAM + Reliable Size; Reliable > Final ⇒ FRAME_ENCODING_ERROR). Empfangsseitig werden die
  ersten Reliable-Size-Bytes weiter zugestellt (Flow-Control bucht dennoch die volle Final Size),
  spätere Frames dürfen die Reliable Size nur senken (§5.2), ein geänderter Fehlercode ⇒
  STREAM_STATE_ERROR. API: `QuicStream.ResetAt(code, reliableSize)` (garantiert bereits gesendete
  Bytes; retransmittiert STREAM-Frames darunter weiter; degradiert ohne Peer-Support zu RESET_STREAM),
  `QuicStream.PeerReliableSize`. **Live über UDP:** Cloudflare akzeptiert den TP 0x1d (Handshake + 200)
- **HTTP-Datagramme (RFC 9297 / RFC 9221):** die Grundlage von MASQUE/WebTransport. QUIC-Schicht:
  Transport-Parameter `max_datagram_frame_size` (0x20) + `DatagramFrame` (0x30/0x31, unfragmentierbar,
  nicht retransmittiert, congestion-controlled); Empfang ohne Ankündigung/über Limit ⇒
  PROTOCOL_VIOLATION. HTTP/3-Schicht: `SETTINGS_H3_DATAGRAM` (0x33) beidseitig, Quarter-Stream-ID-Format,
  Zuordnung zum Extended-CONNECT-Tunnel; unparsbare/zu große ID ⇒ H3_DATAGRAM_ERROR (Verbindungsfehler),
  Datagramm zu einem GET/POST ⇒ Request-Reset (Stream-Fehler). API: `enableDatagrams`,
  `Http3Tunnel.TrySendDatagram/TryReceiveDatagram`. **Live über UDP:** `H3Get --datagrams` — 3/3
  Datagramme über QUIC-DATAGRAM-Frames geecht
- **Priorities (RFC 9218):** `priority`-Header (`u` 0–7, `i`; fehlertolerantes Structured-Fields-
  Parsing) und PRIORITY_UPDATE-Frame (0xF0700, nur Client-Control-Stream — alle §7.2-MUSTs
  durchgesetzt, Updates für ungeöffnete Streams gepuffert, Update überschreibt Header). Der
  QUIC-Sendepfad schedult nach §10: aufsteigende Urgency; gleiche Urgency nicht-inkrementell in
  Request-Reihenfolge, inkrementell per Round-Robin; Control-/QPACK-Streams mit Urgency 0.
  API: `Http3Request.Priority`, `SendPriorityUpdate(streamId, prio)`. **Live über UDP:**
  `H3Get --priorities` — der `u=0`-Download überholt den früher angefragten Default-Download,
  und ein PRIORITY_UPDATE (u=7) stuft einen `u=0`-Prefetch nachträglich zurück
- **Malformed-Erkennung (RFC 9114 §4.1.2/§4.2/§4.3):** strikte Validierung von Pseudo-Header-Regeln
  (Pflicht/Verbot/Reihenfolge/Kontext, keine Pseudo-Header in Trailern), Feldnamen (Kleinschreibung,
  token-Zeichen) und -werten (kein NUL/CR/LF — Smuggling-Schutz), verbindungsspezifischen Feldern
  (`te` nur „trailers") und Content-Length-Konsistenz (Ausnahme HEAD/204/304). Malformed Requests ⇒
  **400** + Stream-Fehler `H3_MESSAGE_ERROR` ohne Handler-Aufruf; malformed Responses werden verworfen
  (`IsResponseMalformed`); eigene malformed Requests wirft der Client lokal. Gültiger CONNECT ⇒ **501**
- **MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2):** beidseitig ankündbar (`maxFieldSectionSize` ⇒
  SETTINGS 0x06, Formel: Name + Wert + 32 je Feld). Sender-seitig respektiert (Client wirft bei zu
  großen Request-Headern, Server stuft zu große Antwort-Header auf 500 herab); empfänger-seitig
  durchgesetzt (Server: **431** ohne Handler-Aufruf + STOP_SENDING `H3_NO_ERROR`; Client: Antwort
  verwerfen, `IsResponseTooLarge`). **Live:** Cloudflare kündigt 131072 an — geparst und respektiert
- **Trailer + Interim-Responses (RFC 9114 §4.1):** `Http3Request.Trailers`/`Http3Response.Trailers`
  (abschließendes HEADERS-Frame nach dem Content, beide Richtungen, getrennt von den Headern) und
  `Http3Response.InterimResponses` — z. B. **103 Early Hints** als eigene 1xx-Sektion(en) vor der
  finalen Antwort, anhand `:status` sauber abgetrennt. Content nach einem Interim ⇒ malformed ⇒
  STREAM-Fehler `H3_MESSAGE_ERROR` (§4.1.2), die Verbindung lebt weiter. **Live über UDP:**
  `H3Get localhost /hints` zeigt `103 (Interim) → 200 → Trailer: checksum: …`
- **GOAWAY / Graceful Shutdown (RFC 9114 §5.2):** `InitiateGracefulShutdown()` kündigt per GOAWAY die
  erste nicht mehr angenommene Request-Stream-ID an; Laufendes wird zu Ende bedient, Späteres mit
  `H3_REQUEST_REJECTED` zurückgewiesen (gefahrlos wiederholbar), am Ende `CloseGracefully()` mit
  **H3_NO_ERROR**. Der Client verweigert nach GOAWAY neue Requests (MUST NOT) und markiert In-Flight-
  Requests ≥ der Grenze als zurückgewiesen; anwachsende GOAWAY-IDs ⇒ `H3_ID_ERROR`. **Live über UDP:**
  `H3Server --goaway` + `H3Get --goaway` — GET 200 → GOAWAY → Request verweigert → CLOSE `0x100`
- **M2 live:** `dotnet run --project samples/H3Get` holt die echte „QUIC | Cloudflare"-Seite
  (Status 200, `content-type: text/html`, `server: cloudflare`, ~126 KB Body)

### QPACK (Phase 6, RFC 9204 — `Http3.Qpack`)

- Encoder/Decoder **ohne dynamische Tabelle** (spec-konform mit `QPACK_MAX_TABLE_CAPACITY=0`)
- Static Table (99 Einträge) + Huffman (RFC 7541 App. B) + N-Bit-Integer-/String-Codec — die
  Huffman-/Static-Tabellen sind per Skript aus den RFCs generiert (keine Handtranskription)
- Verifiziert: RFC-9204-B.1 (Decode), RFC-7541-Huffman-Vektoren, Header-Round-Trips; der Encoder
  bevorzugt Huffman, wenn kürzer, und Indexed/Name-Reference-Formen für Static-Table-Treffer
- **Dynamische Tabelle (RFC 9204 §3):** `QpackDynamicTable` (FIFO mit Byte-Kapazität, Eviction, absolute
  Indizierung), `QpackDynamicEncoder` (erzeugt Insert-Instruktionen für den Encoder-Stream + Field Section,
  Base = Required Insert Count) und `QpackDynamicDecoder` (Set Capacity / Insert With Name Reference
  static+dynamic / Insert With Literal Name / Duplicate; Field Lines indexed static/dynamic, **Post-Base**,
  literale Namen; Required-Insert-Count-Modulo-Rekonstruktion §4.5.1). **Byte-genau gegen RFC-9204-Anhang-B.2
  verifiziert**, plus Encoder↔Decoder-Round-Trip, dynamische Wiederverwendung und Eviction.
- **In HTTP/3 verdrahtet (`Http3Qpack`):** SETTINGS kündigen die Kapazität an; die Uni-Streams des Peers
  (Control + QPACK-Encoder) werden gelesen, Insert-Instruktionen streamend verarbeitet, blockierte HEADERS
  gepuffert und erneut versucht. **Gated:** Kapazität 0 = rein statisch (Standard, Cloudflare-interop-sicher);
  `H3Get --qpack-dynamic` gegen den eigenen Server aktiviert die dynamische Tabelle beidseitig — **live über
  UDP:** Request-Insert (`:authority`) fließt zum Server, Antwort-Inserts (`content-type`/`server`) zurück
  zum Client, Status 200. End-to-end-Test über den vollen Stack (Encoder-Stream-Austausch + Blocked-Retry).
- **Decoder-Stream-Feedback (RFC 9204 §4.4):** Der Decoder sendet nach einer dynamischen Sektion eine
  **Section-Acknowledgment**; der Encoder verarbeitet Section-Ack/Stream-Cancellation/Insert-Count-Increment
  und **gibt die referenzierten Einträge frei**. Die Tabelle verdrängt keinen noch referenzierten Eintrag
  (Eviction-Schutz, §2.1.1) — die Acks halten sie über viele Requests hinweg nutzbar.

### Streams (Phase 4, RFC 9000 §2–§4)

- `StreamId` (Initiator/Richtung-Bits), `StreamReceiveBuffer` (Reassemblierung, FIN/Final-Size,
  Flow-Control), `StreamSendBuffer` (Frame-Erzeugung im Fenster), `QuicStream`
- Flow-Control-Frames (`MAX_DATA`/`MAX_STREAM_DATA`/`MAX_STREAMS`/`*_BLOCKED`),
  `RESET_STREAM`/`STOP_SENDING`; 1-RTT-Sendepfad (`ShortHeader.Build`)
- `QuicClientConnection` routet eingehende STREAM-Frames, dekodiert die Server-Transport-Parameter
  (aus EncryptedExtensions) und beachtet beim Senden Stream- + Verbindungsfenster
- Live: Cloudflares **HTTP/3-Control-Stream (mit SETTINGS)** und die **QPACK-Streams** werden korrekt
  reassembliert und typisiert — direkter Übergang zu HTTP/3 (Phase 7)

### Verbindungsarchitektur (Phase 3b)

- `TlsClientHandshake` (Quic.Tls): treibt den TLS-1.3-Client-Handshake hinter dem etablierten
  „CRYPTO rein / CRYPTO + Keys raus"-Interface (ClientHello, ServerHello, Key-Schedule, Finished,
  App-Secrets). Prüft das Serverzertifikat (CertificateVerify-Signatur + Kette/Hostname) — siehe
  Abschnitt „Zertifikatsprüfung".
- `QuicClientConnection` (Quic): Encryption-Levels, `PacketNumberSpace` je Space,
  CRYPTO-Reassemblierung, Schlüsselinstallation — `Start()` / `GetDatagramsToSend()` /
  `ProcessDatagram()`. Das Sample `H3Get` ist dadurch reines UDP-I/O (~60 Zeilen).

### TLS-Key-Schedule (RFC 8446 §7.1, verifiziert gegen RFC 8448)

- `KeySchedule`: Early → Handshake → Master Secret, `Derive-Secret`, Handshake-/Application-Traffic-
  Secrets — byte-genau gegen die RFC-8448-Traces geprüft
- `Transcript` (`IncrementalHash`), `HandshakeMessages` (Zerlegung des CRYPTO-Stroms)
- `CryptoStreamAssembler` (QUIC): offset-basierte, paketübergreifende CRYPTO-Reassemblierung (Empfang);
  ausgehend verteilt `AppendLevelPackets` große CRYPTO (z. B. den PQ-Hybrid-ClientHello) offset-korrekt
  auf mehrere ≤MTU-Initials/Handshakes — live gegen Cloudflare mit `--mlkem` bestätigt

### Meilenstein M1 — vollständiger Handshake (Sample `samples/H3Get`)

`dotnet run --project samples/H3Get` führt den **kompletten** QUIC/TLS-1.3-Handshake gegen
`cloudflare-quic.com:443` — from scratch, nur BCL:

1. Client-Initial (ClientHello) gesendet, akzeptiert und geACKt
2. **ServerHello** geparst (`AES-128-GCM-SHA256`, TLS 1.3, `key_share=secp256r1`)
3. ECDHE + Transcript(CH‖SH) → Handshake Traffic Secrets
4. **5 Handshake-Pakete entschlüsselt**, CRYPTO reassembliert: EncryptedExtensions, Certificate,
   CertificateVerify, Finished — **Server-Finished-MAC verifiziert**
5. Transcript fortgeschrieben → **eigener (Client-)Finished** berechnet und in einem Handshake-Paket
   gesendet, dazu ACKs für Initial + Handshake
6. **1-RTT-Application-Keys** abgeleitet, und das **HANDSHAKE_DONE** des Servers in einem
   entschlüsselten 1-RTT-Paket empfangen → **Handshake vollständig abgeschlossen**

(In den 1-RTT-Paketen taucht bereits Cloudflares HTTP/3-Control-Stream auf — Vorschau auf Phase 7.)

### TLS 1.3 / ClientHello (RFC 8446, RFC 9001 §8)

- `ClientHello.Build`: vollständige Handshake-Nachricht mit SNI, supported_groups,
  signature_algorithms, supported_versions (TLS 1.3), key_share (P-256), ALPN (`h3`) und
  `quic_transport_parameters`; verifiziert durch strukturelles Zurückparsen
- `EcdheKeyExchange`: P-256/P-384-Schlüsselaustausch (unkomprimierter Punkt, X-Koordinate als Secret)
- `TransportParameters` (QUIC-Schicht): Encode/Decode, ignoriert unbekannte Parameter (Grease)
- `TlsWriter`: längenpräfigierte Vektoren per Back-Patching; `BufferWriter.PatchSpan` ergänzt

### Frames (RFC 9000 §19)

- `Frame`-Basis + `PADDING`, `PING`, `HANDSHAKE_DONE`, `CRYPTO`, `STREAM`, `ACK` (inkl. ECN), `CONNECTION_CLOSE`
- `AckFrame` mit absolutem Bereichsmodell (rechnet Gap-/Längen-Wire-Kodierung um)
- `FrameParser`: zerlegt Payloads, fasst PADDING zusammen, meldet FRAME_ENCODING_ERROR/unbekannte Typen
- Verifiziert: der echte entschlüsselte Server-Initial-Payload (ACK + CRYPTO) aus RFC 9001 A.3
  wird geparst **und** byte-genau zurückserialisiert
- `TransportError`-Codes (RFC 9000 §20.1)

### Paketformate (RFC 9000 §17)

- `ConnectionId` (0–20 Byte, Wertegleichheit, als Demux-Schlüssel nutzbar)
- `PacketNumber`: Encode/Decode + Längenwahl nach RFC 9000 Anhang A (gegen die Beispiele getestet)
- `LongHeader`: Parse (Cleartext-Felder → `PacketNumberOffset`) und Build für Initial/Handshake;
  die aus Feldern gebauten Pakete stimmen byte-genau mit den RFC-9001-Vektoren überein, inkl.
  vollem Sende-→-Empfangs-Round-Trip (bauen → parsen → entschützen → Klartext)
- `ShortHeader`: DCID-/Paketnummern-Lokalisierung anhand bekannter lokaler CID-Länge

### Phase 1 – verifizierte RFC-9001-Vektoren

- **A.1** Key-Schedule: `initial_secret`, Client-/Server-Keys, IVs, HP-Keys, HkdfLabel-Kodierung
- **A.2** Client-Initial (1200 Byte) byte-genau erzeugt + Header-Protection-Maske
- **A.3** Server-Initial byte-genau erzeugt, Header-Maske **und** Entschlüsselungs-Round-Trip
- **A.4** Retry Integrity Tag
- **A.5** ChaCha20-Poly1305: Header-Protection-Maske `aefefe7d03` byte-genau (eigener ChaCha20-Block),
  dazu der RFC-8439-Blockvektor und ein Paket-Round-Trip; die Suite wird ausgehandelt und ist live
  gegen Cloudflare bestätigt (`H3Get … --chacha20`)

Bausteine in `src/Quic/Crypto/`: `TlsHkdf`, `TrafficKeys`, `InitialSecrets`,
`PacketProtection` (AEAD **AES-GCM/ChaCha20-Poly1305** + Header Protection + Paketnummern-Rekonstruktion),
`ChaCha20` (roher Block für die HP-Maske), `RetryIntegrity`.

## Struktur

```
src/Quic.Core/     Gemeinsame Primitive (VarInt aus RFC 9000 §16, Buffer-Reader/Writer, ByteQueue/GsoBatcher) — von allen Schichten genutzt
src/Quic.Tls/      QUIC-TLS-Bindung: TLS 1.3 im QUIC-Profil (Messages, Key-Schedule, ECDHE), kein
                   Record-Layer — ohne Rückverweis auf Quic (referenziert nur Quic.Core)
src/Quic/          QUIC-Transport (Crypto, Packets, Frames, Streams, Connection); nutzt Quic.Tls
src/Http3.Qpack/   QPACK (Static Table, Huffman, Encoder/Decoder)
src/Http3/         HTTP/3 (Frames, Client-/Server-Verbindung, Malformed-Validierung, Priorities,
                   Extended-CONNECT-Tunnel) + WebSocket/ (RFC 6455) + WebTransport/ (draft-13)
                   + async API (Http3Client/Http3Server: Task-Fassaden mit Socket + Hintergrund-Pump)
tests/Http3.Tests/ NUnit-Tests (403), u. a. mit RFC-Testvektoren und „bösen" Roh-QUIC-Peers
samples/H3Get/     HTTP/3-Client: GET/POST gegen cloudflare-quic.com oder den eigenen Server
                   (u. a. --interop [Matrix gegen 8 fremde Stacks], --post, --cancel, --goaway, --priorities, --websocket, --datagrams, --webtransport, --zerortt, --resume, --key-update, --migrate,
                   --rotate-cid, --qpack-dynamic, --mlkem, --x448, --chacha20, --loss, --hold, -k)
samples/H3Server/  HTTP/3-Server: self-signed Cert, Handler über UDP (Routen: /, /big, POST /echo,
                   /hints mit 103 + Trailer; CONNECT websocket/datagram-echo, WebTransport /wt;
                   Optionen u. a. --retry, --idle, --goaway, --ed25519/--ed448/--mldsa)
```

Namespaces: QUIC liegt unter `org.GraphDefined.Vanaheimr.Hermod.Quic` (+ `.Tls`, `.Core`, …) — als
eigenständiger Transport **neben** HTTP/3, nicht darunter; HTTP/3 unter `org.GraphDefined.Vanaheimr.Hermod.HTTP3`
(+ `.Qpack`, `.Tests`). Die Projekt-/Assemblynamen bleiben kurz (Quic, Quic.Tls, …). Alle using-Blöcke
stehen in `#region Usings … #endregion` (Hermod-Stil).

## Bauen & Testen

```bash
dotnet build
dotnet test
```

Voraussetzung: .NET 10 SDK.
