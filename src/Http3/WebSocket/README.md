# WebSocket over HTTP/3 (RFC 9220 / RFC 8441 / RFC 6455)

The files `IHTTP2Tunnel.cs`, `WebSocketConnection.cs`, `WebSocketDeflate.cs`,
`WebSocketMessage.cs`, `WebSocketOpcode.cs`, `WebSocketProtocolException.cs` and
`WebSocketRole.cs` are **byte-identical copies** from the Hermod repository
(`libs/Hermod/Hermod/HTTP2/WebSocket/` and `HTTP2/Core/IHTTP2Tunnel.cs`) —
**only change: the namespace line** (`…Hermod.HTTP2` → `…Hermod.HTTP3`).

The RFC 6455 framing is written transport-agnostically against the 2-method
interface `IHTTP2Tunnel` (`ReadAsync`/`WriteAsync`); for HTTP/3, `Http3Tunnel`
(RFC 9114 §4.4: tunnel bytes travel in DATA frames of the Extended-CONNECT
stream, RFC 8441/9220) implements the same interface.

**Dedup plan:** once this stack is merged into Hermod, both copies move into a
shared transport-neutral namespace (WebSocket core + one tunnel adapter each for
HTTP/2 and HTTP/3) — until then, the minimal diff (only the namespace line)
keeps reconciliation trivial.
