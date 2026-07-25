/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Qlog;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

// ---------------------------------------------------------------------------------------------
// H3Server: a minimal HTTP/3 server, from scratch. Listens on UDP, performs the QUIC/TLS 1.3
// server handshake (self-signed certificate) and answers GET requests. Test e.g. with
//   curl --http3-only -k https://localhost:4433/
// or with our own client (samples/H3Get).
// ---------------------------------------------------------------------------------------------

int port = args.FirstOrDefault(a => int.TryParse(a, out _)) is { } portArg ? int.Parse(portArg) : 4433;

// Optional short idle timeout (RFC 9000 §10.1) to demonstrate reaping: --idle=<ms>.
string? idleArg = args.FirstOrDefault(a => a.StartsWith("--idle=", StringComparison.Ordinal));
ulong idleMs = idleArg is not null && ulong.TryParse(idleArg["--idle=".Length..], out ulong v) ? v : 30_000;
var serverParams = new TransportParameters { MaxIdleTimeoutMs = idleMs };

// Optional address validation via Retry (RFC 9000 §8.1): --retry.
bool requireRetry = args.Contains("--retry");
// --stateless-retry does the same thing the way a server under load has to: the Retry is answered
// from the token alone, BEFORE a connection object exists (§8.1.2). --retry, by contrast, builds the
// connection first and only then sends the Retry — fine for a demo, useless against a flood.
RetryTokenGenerator? addressValidation = args.Contains("--stateless-retry") ? new RetryTokenGenerator() : null;

// Mutual TLS (RFC 8446 §4.3.2): --mtls=<ca.pem> requires a client certificate chaining to that CA,
// --mtls-request=<ca.pem> asks for one but lets an anonymous client through (the handler then sees
// an unauthenticated connection and can answer 403 itself).
string? mtlsRequire = args.FirstOrDefault(a => a.StartsWith("--mtls=", StringComparison.Ordinal))?["--mtls=".Length..];
string? mtlsRequest = args.FirstOrDefault(a => a.StartsWith("--mtls-request=", StringComparison.Ordinal))?["--mtls-request=".Length..];
ClientCertificateOptions? clientCertificates = (mtlsRequire ?? mtlsRequest) is { } caPath
    ? new ClientCertificateOptions
      {
          Mode       = mtlsRequire is not null ? ClientCertificateMode.Require : ClientCertificateMode.Request,
          Validation = new CertificateValidationOptions
                       {
                           VerifyHostname    = false, // a client certificate names a client, not a host
                           CustomTrustRoots  = [X509CertificateLoader.LoadCertificateFromFile(caPath)],
                       },
      }
    : null;
if (clientCertificates is not null)
    Console.WriteLine($"Mutual TLS: client certificates {clientCertificates.Mode} (CA: {mtlsRequire ?? mtlsRequest})");
// --keylog[=<path>]: TLS secrets in NSS key log format for Wireshark (debugging only!).
// --qlog=<dir>: one qlog trace per connection (a qlog trace = exactly one connection).
string? qlogDir = args.FirstOrDefault(a => a.StartsWith("--qlog="))?["--qlog=".Length..];
if (qlogDir is not null)
    Directory.CreateDirectory(qlogDir);
int qlogCounter = 0;
KeyLog? keyLog = args.FirstOrDefault(a => a.StartsWith("--keylog")) is { } keyLogArg
    ? (keyLogArg.StartsWith("--keylog=") ? KeyLog.ToFile(keyLogArg["--keylog=".Length..]) : KeyLog.FromEnvironment())
    : null;

// Optionally demonstrate graceful shutdown (RFC 9114 §5.2): after the first answered request send a
// GOAWAY, then (one exchange later) close with H3_NO_ERROR: --goaway.
bool goAwayDemo = args.Contains("--goaway");

// Optionally an Ed25519, Ed448 or ML-DSA server certificate instead of ECDSA P-256:
// --ed25519 / --ed448 (RFC 8032/8410) or --mldsa (FIPS 204, post-quantum, draft-ietf-tls-mldsa).
bool useEd25519 = args.Contains("--ed25519");
bool useEd448 = args.Contains("--ed448");
bool useMLDsa = args.Contains("--mldsa");

// Optionally prefer a named group: --x448 (RFC 7748) or --mlkem (PQ hybrid X25519MLKEM768).
// For normal clients X25519/P-256 remain as fallback.
IReadOnlyList<NamedGroup>? preferGroups =
    args.Contains("--mlkem") ? [NamedGroup.X25519MlKem768, NamedGroup.X25519, NamedGroup.Secp256r1]
    : args.Contains("--x448") ? [NamedGroup.X448, NamedGroup.X25519, NamedGroup.Secp256r1]
    : null;

using var certificate =
    useMLDsa ? ServerCertificate.CreateSelfSignedMLDsa("localhost")
    : useEd448 ? ServerCertificate.CreateSelfSignedEd448("localhost")
    : useEd25519 ? ServerCertificate.CreateSelfSignedEd25519("localhost")
    : ServerCertificate.CreateSelfSigned("localhost");
// Process-wide ticket store for session resumption (RFC 8446 §4.6.1): one instance for all connections.
var resumptionCache = new ServerResumptionCache();

// Secret for CID-derivable stateless-reset tokens (RFC 9000 §10.3.1). PERSISTS across restarts:
// only with the same secret can a freshly restarted server still send valid (client-recognizable)
// resets for connections built before the restart. Default path next to the exe; changeable via --secret-file=.
string secretPath = args.FirstOrDefault(a => a.StartsWith("--secret-file=", StringComparison.Ordinal)) is { } sfArg
    ? sfArg["--secret-file=".Length..]
    : Path.Combine(AppContext.BaseDirectory, "stateless-reset-secret.bin");
byte[] statelessResetSecret = LoadOrCreateSecret(secretPath, out bool secretCreated);
var statelessResetTokens = new StatelessResetTokenGenerator(statelessResetSecret);

Console.WriteLine($"== HTTP/3 from Scratch — server on UDP/{port} ==");
Console.WriteLine($"Certificate: {certificate.Certificate.Subject} ({certificate.SignatureScheme}, thumbprint {certificate.Certificate.Thumbprint[..16]}…)");
Console.WriteLine($"Idle timeout: {idleMs} ms (announced; effectively at least 3·PTO)");
Console.WriteLine($"Stateless-reset secret: {secretPath} ({(secretCreated ? "newly created" : "loaded — survives restarts")})");
if (requireRetry)
    Console.WriteLine("Address validation: Retry active (every new connection first receives a Retry)");
Console.WriteLine("Waiting for HTTP/3 clients … (Ctrl+C to stop)\n");

using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1000 };
socket.Bind(new IPEndPoint(IPAddress.Any, port));

// Connections are demultiplexed primarily via the connection ID (not via the address), so that a
// connection migration (RFC 9000 §9) — a client changing its address — hits the same connection.
var connections = new List<ServerConn>();
var datagramEchoTunnels = new List<Http3Tunnel>(); // "datagram-echo" tunnels (RFC 9297): echo in the main loop
var webTransportSessions = new List<WebTransportSession>(); // WebTransport sessions: echo in the main loop
var wtEchoStreams = new List<(WebTransportStream In, WebTransportStream? Reply)>();
var wtEchoBuffers = new Dictionary<WebTransportStream, List<byte>>();
byte[] buffer = new byte[2048];

while (true)
{
    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
    int n;
    try
    {
        n = socket.ReceiveFrom(buffer, ref from);
    }
    catch (SocketException)
    {
        // Timeout: check the timers of all connections (loss detection + idle) and resend if needed.
        foreach (ServerConn sc in connections)
        {
            sc.Connection.CheckTimeouts();
            if (!sc.Connection.IsIdleTimedOut)
                foreach (byte[] dg in sc.Connection.GetDatagramsToSend())
                    socket.SendTo(dg, sc.Endpoint);
        }
        connections.RemoveAll(sc =>
        {
            if (!sc.Connection.IsIdleTimedOut) return false;
            Console.WriteLine($"Connection from {sc.Endpoint} closed after idle timeout.");
            sc.Connection.Dispose();
            return true;
        });
        continue;
    }

    ReadOnlySpan<byte> datagram = buffer.AsSpan(0, n);

    // 1) Find via the destination connection ID (stable after the handshake, even on an address change).
    ServerConn? conn = ExtractDcid(datagram) is { } dcid
        ? connections.FirstOrDefault(c => c.Connection.OwnsConnectionId(dcid))
        : null;
    // 2) Otherwise via the sender address (handshake / new connection).
    conn ??= connections.FirstOrDefault(c => c.Endpoint.Equals(from));

    if (conn is null)
    {
        byte first = datagram.Length > 0 ? datagram[0] : (byte)0;

        // A 1-RTT packet (short header) for an unknown DCID belongs to a lost connection ⇒
        // send a stateless reset (RFC 9000 §10.3), do not open a new connection.
        if (datagram.Length > 0 && PacketFormat.IsShortHeader(first))
        {
            if (StatelessReset.BuildResponse(datagram, localCidLength: 8, statelessResetTokens) is { } reset)
            {
                socket.SendTo(reset, from);
                Console.WriteLine($"Stateless reset sent to {from} (unknown connection ID, RFC 9000 §10.3).");
            }
            continue;
        }

        // Only a genuine Initial packet opens a new connection; other long headers (Handshake/0-RTT) for
        // an unknown connection are dropped (RFC 9000 §5.2) so they do not wrongly create a connection.
        if (!PacketFormat.IsLongHeader(first) || PacketFormat.GetLongPacketType(first) != LongPacketType.Initial)
            continue;

        // Stateless address validation (RFC 9000 §8.1.2) — before ANY state is allocated.
        QuicServerConnection.ValidatedRetry? validatedRetry = null;
        if (addressValidation is { } tokens)
        {
            if (datagram.Length < InitialPacketFactory.MinimumClientInitialSize ||
                !LongHeader.TryParse(datagram, out LongHeaderPrefix? initial) || initial is null)
                continue;

            if (initial.Token.Length == 0)
            {
                var retryScid = new ConnectionId(RandomNumberGenerator.GetBytes(8));
                byte[] retry = RetryPacket.Build(initial.Version, initial.SourceConnectionId, retryScid,
                                                 tokens.Issue((IPEndPoint)from, initial.DestinationConnectionId, retryScid),
                                                 initial.DestinationConnectionId);
                socket.SendTo(retry, from);
                Console.WriteLine($"Retry sent to {from} (address validation, no state held).");
                continue;
            }

            if (!tokens.TryValidate(initial.Token, (IPEndPoint)from, out ConnectionId odcid, out ConnectionId issuedScid) ||
                !initial.DestinationConnectionId.Equals(issuedScid) ||
                !tokens.TryConsume(initial.Token))
            {
                byte[] refusal = StatelessClose.Build(initial.Version, initial.DestinationConnectionId,
                                                      initial.SourceConnectionId, TransportError.InvalidToken,
                                                      "invalid retry token");
                socket.SendTo(refusal, from);
                Console.WriteLine($"INVALID_TOKEN sent to {from} (RFC 9000 §8.1.2).");
                continue;
            }

            validatedRetry = new QuicServerConnection.ValidatedRetry(odcid, issuedScid);
            Console.WriteLine($"Address of {from} validated via Retry token.");
        }

        conn = new ServerConn(new Http3ServerConnection(certificate, Handle, serverParams, requireRetry,
            preferredGroups: preferGroups, resumptionCache: resumptionCache, maxEarlyDataSize: 0xFFFFFFFF,
            statelessResetTokens: statelessResetTokens,
            keyLog: keyLog,
            qlog: qlogDir is null ? null
                : QlogWriter.ToFile(Path.Combine(qlogDir, $"conn-{++qlogCounter:D3}.sqlog"), isServer: true),
            maxFieldSectionSize: 16_384,        // RFC 9114 §4.2.2: oversized request headers ⇒ 431
            maxRequestBodySize: 8 * 1024 * 1024, // buffered bodies above this ⇒ 413 (own limit)
            connectHandler: HandleConnect,      // RFC 9220: WebSockets via Extended CONNECT
            enableDatagrams: true,              // RFC 9297/9221: HTTP datagrams
            webTransportMaxSessions: 4,         // draft-webtrans-http3: WebTransport
            webTransportHandler: HandleWebTransport,
            webTransportProtocolSelector: SelectWebTransportProtocol, // draft §3.3
            validatedRetry: validatedRetry,
            clientCertificate: clientCertificates), from);
        connections.Add(conn);
        Console.WriteLine($"New connection from {from}");
    }
    else if (!conn.Endpoint.Equals(from))
    {
        // Connection migration (RFC 9000 §9): known connection from a new address → validate the new path.
        Console.WriteLine($"Connection migration: {conn.Endpoint} → {from} — validating new path (PATH_CHALLENGE) …");
        conn.Endpoint = from;
        conn.Connection.InitiatePathValidation();
    }

    conn.Connection.ProcessDatagram(datagram);

    // Graceful-shutdown demo (RFC 9114 §5.2): first announce GOAWAY (and flush), then in the NEXT
    // exchange — provided nothing is outstanding — close decently with H3_NO_ERROR.
    if (goAwayDemo && !conn.Connection.IsClosing && !conn.Connection.IsDraining)
    {
        if (conn.GoAwayAnnounced && !conn.Connection.HasPendingRequests)
        {
            Console.WriteLine("→ All accepted requests served — CONNECTION_CLOSE (H3_NO_ERROR).");
            conn.Connection.CloseGracefully();
        }
        else if (conn.Connection.RequestsHandled > 0 && conn.Connection.GoAwaySent is null)
        {
            conn.Connection.InitiateGracefulShutdown();
            conn.GoAwayAnnounced = true;
            Console.WriteLine($"→ GOAWAY sent (limit: stream ID {conn.Connection.GoAwaySent}) — graceful shutdown (RFC 9114 §5.2).");
        }
    }

    // Serve "datagram-echo" tunnels (RFC 9297): mirror received HTTP datagrams back.
    foreach (Http3Tunnel echoTunnel in datagramEchoTunnels)
        while (echoTunnel.TryReceiveDatagram(out byte[]? payload) && payload is not null)
        {
            Console.WriteLine($"  ← HTTP datagram ({payload.Length} bytes) — echoing back (unreliable, RFC 9297).");
            echoTunnel.TrySendDatagram(payload);
        }

    // Serve WebTransport sessions: mirror datagrams + incoming streams back (echo).
    foreach (WebTransportSession wt in webTransportSessions)
    {
        while (wt.TryReceiveDatagram(out byte[]? dgram) && dgram is not null)
        {
            Console.WriteLine($"  ← WT datagram ({dgram.Length} bytes) — echo.");
            wt.SendDatagram(dgram);
        }
        // Accept incoming uni/bidi streams and send the body back.
        while (wt.AcceptUnidirectionalStream() is { } uni)
            wtEchoStreams.Add((uni, null));
        while (wt.AcceptBidirectionalStream() is { } bidi)
            wtEchoStreams.Add((bidi, bidi));
    }
    for (int i = wtEchoStreams.Count - 1; i >= 0; i--)
    {
        (WebTransportStream inStream, WebTransportStream? reply) = wtEchoStreams[i];
        wtEchoBuffers.TryAdd(inStream, []);
        wtEchoBuffers[inStream].AddRange(inStream.Read());
        if (inStream.IsReceiveComplete)
        {
            byte[] body = [.. wtEchoBuffers[inStream]];
            Console.WriteLine($"  ← WT stream ({(reply is null ? "uni" : "bidi")}, {body.Length} bytes: \"{Encoding.UTF8.GetString(body)}\")");
            if (reply is not null) { reply.Write(body); reply.Finish(); } // bidi ⇒ echo back
            wtEchoBuffers.Remove(inStream);
            wtEchoStreams.RemoveAt(i);
        }
    }

    foreach (byte[] dg in conn.Connection.GetDatagramsToSend())
        socket.SendTo(dg, conn.Endpoint);

    if (conn.Connection.PathValidated && !conn.PathAnnounced)
    {
        conn.PathAnnounced = true;
        Console.WriteLine($"  ✓ New path {conn.Endpoint} validated (PATH_RESPONSE received).");
    }

    // Decent teardown (RFC 9000 §10.2): the peer sent CONNECTION_CLOSE → draining → weed out.
    if (conn.Connection.IsDraining)
    {
        string reason = conn.Connection.PeerCloseFrame?.ReasonPhrase is { Length: > 0 } r ? $" — \"{r}\"" : "";
        Console.WriteLine($"Peer {conn.Endpoint} closed the connection (error code {conn.Connection.PeerCloseFrame?.ErrorCode}){reason}.");
        conn.Connection.Dispose();
        connections.Remove(conn);
    }
}

// Extracts the (version-independent) destination connection ID of a datagram; local CIDs are 8 bytes.
static ConnectionId? ExtractDcid(ReadOnlySpan<byte> datagram)
{
    if (datagram.IsEmpty)
        return null;
    if (PacketFormat.IsLongHeader(datagram[0]))
        return LongHeader.TryParseInvariant(datagram, out _, out ConnectionId dcid, out _) ? dcid : null;
    const int localCidLength = 8;
    return datagram.Length >= 1 + localCidLength ? new ConnectionId(datagram.Slice(1, localCidLength)) : null;
}

// Loads the 32-byte stateless-reset secret from <paramref name="path"/> or creates and stores a new one.
// Stable across restarts, so that the tokens derived from the CID (RFC 9000 §10.3.1) stay the same.
// Security note: the file is a cryptographic secret (whoever has it can forge resets).
static byte[] LoadOrCreateSecret(string path, out bool created)
{
    if (File.Exists(path))
    {
        byte[] existing = File.ReadAllBytes(path);
        if (existing.Length == 32)
        {
            created = false;
            return existing;
        }
    }
    byte[] fresh = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    File.WriteAllBytes(path, fresh);
    created = true;
    return fresh;
}

// Extended CONNECT (RFC 8441/9220): :protocol "websocket" ⇒ WebSocket echo over the tunnel;
// "datagram-echo" ⇒ mirror HTTP datagrams back (RFC 9297); everything else ⇒ 501 (RFC 9220 §3 SHOULD).
Http3ConnectResult HandleConnect(Http3Request request)
{
    Console.WriteLine($"  → CONNECT :protocol={request.Protocol}  (:path={request.Path})");

    if (request.Protocol == "datagram-echo")
        return new Http3ConnectResult
        {
            Status = 200,
            OnTunnel = tunnel => datagramEchoTunnels.Add(tunnel), // the main loop takes over the echo
        };

    if (request.Protocol != "websocket")
        return new Http3ConnectResult { Status = 501 };

    bool deflate = WebSocketDeflate.ShouldAccept(
        request.AdditionalHeaders.FirstOrDefault(h => h.Name == "sec-websocket-extensions").Value,
        out string? extensionsResponse);

    return new Http3ConnectResult
    {
        Status = 200,
        Headers = deflate ? [new HeaderField("sec-websocket-extensions", extensionsResponse!)] : [],
        OnTunnel = tunnel =>
        {
            var ws = new WebSocketConnection(tunnel, WebSocketRole.Server, deflate);
            _ = EchoWebSocket(ws, tunnel);
        },
    };
}

// RFC 6455 echo: mirror text/binary messages back until the close handshake (or a FIN) ends it.
static async Task EchoWebSocket(WebSocketConnection ws, Http3Tunnel tunnel)
{
    while (await ws.ReceiveAsync(CancellationToken.None) is { } message)
    {
        if (message.Opcode == WebSocketOpcode.Text)
        {
            string text = Encoding.UTF8.GetString(message.Payload);
            Console.WriteLine($"  ← WebSocket text: \"{text}\" — echoing back.");
            await ws.SendTextAsync(text, CancellationToken.None);
        }
        else
            await ws.SendBinaryAsync(message.Payload, CancellationToken.None);
    }
    tunnel.Complete(); // orderly tunnel end (FIN ≙ TCP close, RFC 9220 §3)
    Console.WriteLine("  ✓ WebSocket closed (close handshake performed).");
}

// WebTransport (draft-webtrans-http3): accept /wt, otherwise 404. Echo for datagrams + incoming streams.
Action<WebTransportSession>? HandleWebTransport(Http3Request request)
{
    Console.WriteLine($"  → WebTransport CONNECT :path={request.Path}");
    if (request.Path != "/wt")
        return null; // ⇒ 404 (draft §3.2)
    return session =>
    {
        webTransportSessions.Add(session);
        Console.WriteLine($"  ✓ WebTransport session {session.SessionId} established"
                          + (session.NegotiatedProtocol is { } p ? $" (WT-Protocol: {p})." : "."));
        // Keying-material exporter (draft §4.7): must match the client byte for byte.
        byte[] ekm = session.ExportKeyingMaterial("demo-export", [1, 2, 3], 16);
        Console.WriteLine($"  → Keying-material export (label \"demo-export\"): {Convert.ToHexString(ekm).ToLowerInvariant()}");
    };
}

// Protocol negotiation (draft-webtrans-http3 §3.3): we speak echo-v2/echo-v1 — the client's offer
// list is sorted by preference, so its best offer that we support wins.
static string? SelectWebTransportProtocol(Http3Request request, IReadOnlyList<string> offered)
{
    Console.WriteLine($"  → WT-Available-Protocols: {string.Join(", ", offered)}");
    return offered.FirstOrDefault(p => p is "echo-v2" or "echo-v1");
}

static Http3Response Handle(Http3Request request)
{
    Console.WriteLine($"  → {request.Method} {request.Path}  (:authority={request.Authority}"
                      + (request.Body.Length > 0 ? $", body {request.Body.Length} bytes" : "") + ")");

    // GET /big: ~300 KB deterministic body — playground for prioritization (RFC 9218) and transfers.
    if (request.Path == "/big")
    {
        byte[] bigBody = new byte[300_000];
        for (int i = 0; i < bigBody.Length; i++)
            bigBody[i] = (byte)(i * 13 + 5);
        return new Http3Response
        {
            Status = 200,
            Headers = [new HeaderField("content-type", "application/octet-stream"), new HeaderField("server", "http3-from-scratch")],
            Body = bigBody,
        };
    }

    // GET /hints: 103 Early Hints (interim response, RFC 9110 §15.2.2) before the final response and
    // a trailer section with a checksum after it (RFC 9114 §4.1: HEADERS(1xx) → HEADERS → DATA → HEADERS).
    if (request.Path == "/hints")
    {
        byte[] hintsBody = Encoding.UTF8.GetBytes("<html><head><title>Early Hints</title></head><body>Body after 103.</body></html>");
        return new Http3Response
        {
            Status = 200,
            Headers = [new HeaderField("content-type", "text/html; charset=utf-8"), new HeaderField("server", "http3-from-scratch")],
            Body = hintsBody,
            InterimResponses = [new Http3InterimResponse(103, [new HeaderField("link", "</style.css>; rel=preload; as=style")])],
            Trailers = [new HeaderField("checksum",
                Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(hintsBody))[..16].ToLowerInvariant())],
        };
    }

    // POST /echo: mirror the request body back byte for byte (RFC 9114 §4.1 — content in DATA frames).
    if (request.Method == "POST" && request.Path == "/echo")
        return new Http3Response
        {
            Status = 200,
            Headers =
            [
                new HeaderField("content-type",
                    request.AdditionalHeaders.FirstOrDefault(h => h.Name == "content-type").Value ?? "application/octet-stream"),
                new HeaderField("server", "http3-from-scratch"),
            ],
            Body = request.Body,
        };

    string html = $"""
        <!DOCTYPE html>
        <html><head><title>HTTP/3 from Scratch</title></head>
        <body>
          <h1>Hello from a hand-built HTTP/3 server!</h1>
          <p>You requested <code>{request.Method} {request.Path}</code>.</p>
          <p>QUIC + TLS 1.3 + QPACK + HTTP/3 — all from scratch on .NET, BCL only.</p>
        </body></html>
        """;
    return new Http3Response
    {
        Status = 200,
        Headers = [new HeaderField("content-type", "text/html; charset=utf-8"), new HeaderField("server", "http3-from-scratch")],
        Body = Encoding.UTF8.GetBytes(html),
    };
}

// A server connection together with its current peer address (which may change on migration).
sealed class ServerConn(Http3ServerConnection connection, EndPoint endpoint)
{
    public Http3ServerConnection Connection { get; } = connection;
    public EndPoint Endpoint { get; set; } = endpoint;
    public bool PathAnnounced { get; set; }
    public bool GoAwayAnnounced { get; set; } // GOAWAY already sent (graceful-shutdown demo)
}
