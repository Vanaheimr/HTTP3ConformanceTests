# WebSocket über HTTP/3 (RFC 9220 / RFC 8441 / RFC 6455)

Die Dateien `IHTTP2Tunnel.cs`, `WebSocketConnection.cs`, `WebSocketDeflate.cs`,
`WebSocketMessage.cs`, `WebSocketOpcode.cs`, `WebSocketProtocolException.cs` und
`WebSocketRole.cs` sind **byte-identische Kopien** aus dem Hermod-Repository
(`libs/Hermod/Hermod/HTTP2/WebSocket/` bzw. `HTTP2/Core/IHTTP2Tunnel.cs`) —
**einzige Änderung: die Namespace-Zeile** (`…Hermod.HTTP2` → `…Hermod.HTTP3`).

Das RFC-6455-Framing ist transport-agnostisch gegen das 2-Methoden-Interface
`IHTTP2Tunnel` (`ReadAsync`/`WriteAsync`) geschrieben; für HTTP/3 implementiert
`Http3Tunnel` (RFC 9114 §4.4: Tunnel-Bytes reisen in DATA-Frames des
Extended-CONNECT-Streams, RFC 8441/9220) dasselbe Interface.

**Dedup-Plan:** Sobald dieser Stack in Hermod aufgeht, wandern beide Kopien in
einen gemeinsamen transport-neutralen Namespace (WebSocket-Kern + je ein
Tunnel-Adapter für HTTP/2 und HTTP/3) — bis dahin hält der minimale Diff
(nur die Namespace-Zeile) den Abgleich trivial.
