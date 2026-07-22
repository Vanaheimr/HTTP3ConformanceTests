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
using System.Text;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;

#endregion

// ---------------------------------------------------------------------------------------------
// H3Server: Ein minimaler HTTP/3-Server, from scratch. Lauscht auf UDP, führt den QUIC/TLS-1.3-
// Server-Handshake (selbstsigniertes Zertifikat) und beantwortet GET-Anfragen. Test z. B. mit
//   curl --http3-only -k https://localhost:4433/
// oder mit dem eigenen Client (samples/H3Get).
// ---------------------------------------------------------------------------------------------

int port = args.FirstOrDefault(a => int.TryParse(a, out _)) is { } portArg ? int.Parse(portArg) : 4433;

// Optionaler kurzer Idle-Timeout (RFC 9000 §10.1) zum Vorführen des Reapings: --idle=<ms>.
string? idleArg = args.FirstOrDefault(a => a.StartsWith("--idle=", StringComparison.Ordinal));
ulong idleMs = idleArg is not null && ulong.TryParse(idleArg["--idle=".Length..], out ulong v) ? v : 30_000;
var serverParams = new TransportParameters { MaxIdleTimeoutMs = idleMs };

// Optionale Adressvalidierung per Retry (RFC 9000 §8.1): --retry.
bool requireRetry = args.Contains("--retry");

// Optional Graceful Shutdown vorführen (RFC 9114 §5.2): nach der ersten beantworteten Anfrage ein
// GOAWAY senden, dann (einen Austausch später) mit H3_NO_ERROR schließen: --goaway.
bool goAwayDemo = args.Contains("--goaway");

// Optional ein Ed25519-, Ed448- oder ML-DSA-Serverzertifikat statt ECDSA-P-256:
// --ed25519 / --ed448 (RFC 8032/8410) bzw. --mldsa (FIPS 204, Post-Quantum, draft-ietf-tls-mldsa).
bool useEd25519 = args.Contains("--ed25519");
bool useEd448 = args.Contains("--ed448");
bool useMLDsa = args.Contains("--mldsa");

// Optional eine Named Group bevorzugen: --x448 (RFC 7748) oder --mlkem (PQ-Hybrid X25519MLKEM768).
// Für normale Clients bleiben X25519/P-256 als Rückfall.
IReadOnlyList<NamedGroup>? preferGroups =
    args.Contains("--mlkem") ? [NamedGroup.X25519MlKem768, NamedGroup.X25519, NamedGroup.Secp256r1]
    : args.Contains("--x448") ? [NamedGroup.X448, NamedGroup.X25519, NamedGroup.Secp256r1]
    : null;

using var certificate =
    useMLDsa ? ServerCertificate.CreateSelfSignedMLDsa("localhost")
    : useEd448 ? ServerCertificate.CreateSelfSignedEd448("localhost")
    : useEd25519 ? ServerCertificate.CreateSelfSignedEd25519("localhost")
    : ServerCertificate.CreateSelfSigned("localhost");
// Prozessweiter Ticket-Store für Session Resumption (RFC 8446 §4.6.1): eine Instanz für alle Verbindungen.
var resumptionCache = new ServerResumptionCache();

// Geheimnis für aus der CID ableitbare Stateless-Reset-Tokens (RFC 9000 §10.3.1). PERSISTIERT über Neustarts:
// nur mit demselben Geheimnis kann ein neu gestarteter Server für vor dem Neustart aufgebaute Verbindungen
// noch gültige (vom Client erkennbare) Resets senden. Standardpfad neben der Exe; via --secret-file= änderbar.
string secretPath = args.FirstOrDefault(a => a.StartsWith("--secret-file=", StringComparison.Ordinal)) is { } sfArg
    ? sfArg["--secret-file=".Length..]
    : Path.Combine(AppContext.BaseDirectory, "stateless-reset-secret.bin");
byte[] statelessResetSecret = LoadOrCreateSecret(secretPath, out bool secretCreated);
var statelessResetTokens = new StatelessResetTokenGenerator(statelessResetSecret);

Console.WriteLine($"== HTTP/3 from Scratch — Server auf UDP/{port} ==");
Console.WriteLine($"Zertifikat: {certificate.Certificate.Subject} ({certificate.SignatureScheme}, Thumbprint {certificate.Certificate.Thumbprint[..16]}…)");
Console.WriteLine($"Idle-Timeout: {idleMs} ms (angekündigt; effektiv mind. 3·PTO)");
Console.WriteLine($"Stateless-Reset-Geheimnis: {secretPath} ({(secretCreated ? "neu erzeugt" : "geladen — überlebt Neustarts")})");
if (requireRetry)
    Console.WriteLine("Adressvalidierung: Retry aktiv (jede neue Verbindung erhält zuerst ein Retry)");
Console.WriteLine("Warte auf HTTP/3-Clients … (Strg+C zum Beenden)\n");

using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1000 };
socket.Bind(new IPEndPoint(IPAddress.Any, port));

// Verbindungen werden vorrangig über die Connection ID demultiplext (nicht über die Adresse), damit
// eine Connection Migration (RFC 9000 §9) – ein Client, der die Adresse wechselt – dieselbe Verbindung trifft.
var connections = new List<ServerConn>();
var datagramEchoTunnels = new List<Http3Tunnel>(); // „datagram-echo"-Tunnel (RFC 9297): Echo in der Hauptschleife
var webTransportSessions = new List<WebTransportSession>(); // WebTransport-Sessions: Echo in der Hauptschleife
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
        // Timeout: Timer aller Verbindungen prüfen (Loss Detection + Idle) und ggf. nachsenden.
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
            Console.WriteLine($"Verbindung von {sc.Endpoint} nach Idle-Timeout geschlossen.");
            sc.Connection.Dispose();
            return true;
        });
        continue;
    }

    ReadOnlySpan<byte> datagram = buffer.AsSpan(0, n);

    // 1) Über die Ziel-Connection-ID finden (nach dem Handshake stabil, auch bei Adresswechsel).
    ServerConn? conn = ExtractDcid(datagram) is { } dcid
        ? connections.FirstOrDefault(c => c.Connection.OwnsConnectionId(dcid))
        : null;
    // 2) Sonst über die Absenderadresse (Handshake / neue Verbindung).
    conn ??= connections.FirstOrDefault(c => c.Endpoint.Equals(from));

    if (conn is null)
    {
        byte first = datagram.Length > 0 ? datagram[0] : (byte)0;

        // Ein 1-RTT-Paket (Short Header) zu unbekannter DCID gehört zu einer verlorenen Verbindung ⇒
        // Stateless Reset senden (RFC 9000 §10.3), keine neue Verbindung öffnen.
        if (datagram.Length > 0 && PacketFormat.IsShortHeader(first))
        {
            if (StatelessReset.BuildResponse(datagram, localCidLength: 8, statelessResetTokens) is { } reset)
            {
                socket.SendTo(reset, from);
                Console.WriteLine($"Stateless Reset an {from} gesendet (unbekannte Connection ID, RFC 9000 §10.3).");
            }
            continue;
        }

        // Nur ein echtes Initial-Paket eröffnet eine neue Verbindung; andere Long-Header (Handshake/0-RTT) zu
        // unbekannter Verbindung werden verworfen (RFC 9000 §5.2), damit sie nicht fälschlich eine Verbindung anlegen.
        if (!PacketFormat.IsLongHeader(first) || PacketFormat.GetLongPacketType(first) != LongPacketType.Initial)
            continue;

        conn = new ServerConn(new Http3ServerConnection(certificate, Handle, serverParams, requireRetry,
            preferredGroups: preferGroups, resumptionCache: resumptionCache, maxEarlyDataSize: 0xFFFFFFFF,
            statelessResetTokens: statelessResetTokens,
            maxFieldSectionSize: 16_384,        // RFC 9114 §4.2.2: zu große Request-Header ⇒ 431
            connectHandler: HandleConnect,      // RFC 9220: WebSockets über Extended CONNECT
            enableDatagrams: true,              // RFC 9297/9221: HTTP-Datagramme
            webTransportMaxSessions: 4,         // draft-webtrans-http3: WebTransport
            webTransportHandler: HandleWebTransport,
            webTransportProtocolSelector: SelectWebTransportProtocol), from); // draft §3.3
        connections.Add(conn);
        Console.WriteLine($"Neue Verbindung von {from}");
    }
    else if (!conn.Endpoint.Equals(from))
    {
        // Connection Migration (RFC 9000 §9): bekannte Verbindung von neuer Adresse → neuen Pfad validieren.
        Console.WriteLine($"Connection Migration: {conn.Endpoint} → {from} — validiere neuen Pfad (PATH_CHALLENGE) …");
        conn.Endpoint = from;
        conn.Connection.InitiatePathValidation();
    }

    conn.Connection.ProcessDatagram(datagram);

    // Graceful-Shutdown-Demo (RFC 9114 §5.2): erst GOAWAY ankündigen (und flushen), im NÄCHSTEN
    // Austausch dann — sofern nichts mehr aussteht — anständig mit H3_NO_ERROR schließen.
    if (goAwayDemo && !conn.Connection.IsClosing && !conn.Connection.IsDraining)
    {
        if (conn.GoAwayAnnounced && !conn.Connection.HasPendingRequests)
        {
            Console.WriteLine("→ Alle angenommenen Requests bedient — CONNECTION_CLOSE (H3_NO_ERROR).");
            conn.Connection.CloseGracefully();
        }
        else if (conn.Connection.RequestsHandled > 0 && conn.Connection.GoAwaySent is null)
        {
            conn.Connection.InitiateGracefulShutdown();
            conn.GoAwayAnnounced = true;
            Console.WriteLine($"→ GOAWAY gesendet (Grenze: Stream-ID {conn.Connection.GoAwaySent}) — Graceful Shutdown (RFC 9114 §5.2).");
        }
    }

    // „datagram-echo"-Tunnel bedienen (RFC 9297): empfangene HTTP-Datagramme zurückspiegeln.
    foreach (Http3Tunnel echoTunnel in datagramEchoTunnels)
        while (echoTunnel.TryReceiveDatagram(out byte[]? payload) && payload is not null)
        {
            Console.WriteLine($"  ← HTTP-Datagramm ({payload.Length} Bytes) — Echo zurück (unzuverlässig, RFC 9297).");
            echoTunnel.TrySendDatagram(payload);
        }

    // WebTransport-Sessions bedienen: Datagramme + eingehende Streams zurückspiegeln (Echo).
    foreach (WebTransportSession wt in webTransportSessions)
    {
        while (wt.TryReceiveDatagram(out byte[]? dgram) && dgram is not null)
        {
            Console.WriteLine($"  ← WT-Datagramm ({dgram.Length} Bytes) — Echo.");
            wt.SendDatagram(dgram);
        }
        // Eingehende uni-/bidi-Streams annehmen und den Rumpf zurückschicken.
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
            Console.WriteLine($"  ← WT-Stream ({(reply is null ? "uni" : "bidi")}, {body.Length} Bytes: „{Encoding.UTF8.GetString(body)}\")");
            if (reply is not null) { reply.Write(body); reply.Finish(); } // bidi ⇒ Echo zurück
            wtEchoBuffers.Remove(inStream);
            wtEchoStreams.RemoveAt(i);
        }
    }

    foreach (byte[] dg in conn.Connection.GetDatagramsToSend())
        socket.SendTo(dg, conn.Endpoint);

    if (conn.Connection.PathValidated && !conn.PathAnnounced)
    {
        conn.PathAnnounced = true;
        Console.WriteLine($"  ✓ Neuer Pfad {conn.Endpoint} validiert (PATH_RESPONSE erhalten).");
    }

    // Anständiger Abbau (RFC 9000 §10.2): Peer hat CONNECTION_CLOSE gesendet → Draining → aussortieren.
    if (conn.Connection.IsDraining)
    {
        string reason = conn.Connection.PeerCloseFrame?.ReasonPhrase is { Length: > 0 } r ? $" – „{r}\"" : "";
        Console.WriteLine($"Peer {conn.Endpoint} schloss die Verbindung (Fehlercode {conn.Connection.PeerCloseFrame?.ErrorCode}){reason}.");
        conn.Connection.Dispose();
        connections.Remove(conn);
    }
}

// Extrahiert die (versionsunabhängige) Destination Connection ID eines Datagramms; lokale CIDs sind 8 Byte.
static ConnectionId? ExtractDcid(ReadOnlySpan<byte> datagram)
{
    if (datagram.IsEmpty)
        return null;
    if (PacketFormat.IsLongHeader(datagram[0]))
        return LongHeader.TryParseInvariant(datagram, out _, out ConnectionId dcid, out _) ? dcid : null;
    const int localCidLength = 8;
    return datagram.Length >= 1 + localCidLength ? new ConnectionId(datagram.Slice(1, localCidLength)) : null;
}

// Lädt das 32-Byte-Stateless-Reset-Geheimnis aus <paramref name="path"/> oder erzeugt und speichert es neu.
// Über Neustarts hinweg stabil, damit die aus der CID abgeleiteten Tokens (RFC 9000 §10.3.1) gleich bleiben.
// Sicherheitshinweis: Die Datei ist ein kryptografisches Geheimnis (wer sie hat, kann Resets fälschen).
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

// Extended CONNECT (RFC 8441/9220): :protocol „websocket" ⇒ WebSocket-Echo über den Tunnel;
// „datagram-echo" ⇒ HTTP-Datagramme (RFC 9297) zurückspiegeln; alles andere ⇒ 501 (RFC 9220 §3 SHOULD).
Http3ConnectResult HandleConnect(Http3Request request)
{
    Console.WriteLine($"  → CONNECT :protocol={request.Protocol}  (:path={request.Path})");

    if (request.Protocol == "datagram-echo")
        return new Http3ConnectResult
        {
            Status = 200,
            OnTunnel = tunnel => datagramEchoTunnels.Add(tunnel), // Echo übernimmt die Hauptschleife
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

// RFC-6455-Echo: Text-/Binärnachrichten zurückspiegeln, bis der Close-Handshake (oder ein FIN) endet.
static async Task EchoWebSocket(WebSocketConnection ws, Http3Tunnel tunnel)
{
    while (await ws.ReceiveAsync(CancellationToken.None) is { } message)
    {
        if (message.Opcode == WebSocketOpcode.Text)
        {
            string text = Encoding.UTF8.GetString(message.Payload);
            Console.WriteLine($"  ← WebSocket-Text: „{text}\" — Echo zurück.");
            await ws.SendTextAsync(text, CancellationToken.None);
        }
        else
            await ws.SendBinaryAsync(message.Payload, CancellationToken.None);
    }
    tunnel.Complete(); // geordnetes Tunnel-Ende (FIN ≙ TCP-Close, RFC 9220 §3)
    Console.WriteLine("  ✓ WebSocket geschlossen (Close-Handshake vollzogen).");
}

// WebTransport (draft-webtrans-http3): /wt annehmen, sonst 404. Echo für Datagramme + eingehende Streams.
Action<WebTransportSession>? HandleWebTransport(Http3Request request)
{
    Console.WriteLine($"  → WebTransport CONNECT :path={request.Path}");
    if (request.Path != "/wt")
        return null; // ⇒ 404 (draft §3.2)
    return session =>
    {
        webTransportSessions.Add(session);
        Console.WriteLine($"  ✓ WebTransport-Session {session.SessionId} etabliert"
                          + (session.NegotiatedProtocol is { } p ? $" (WT-Protocol: {p})." : "."));
        // Keying-Material-Exporter (draft §4.7): muss byte-genau mit dem Client übereinstimmen.
        byte[] ekm = session.ExportKeyingMaterial("demo-export", [1, 2, 3], 16);
        Console.WriteLine($"  → Keying-Material-Export (Label \"demo-export\"): {Convert.ToHexString(ekm).ToLowerInvariant()}");
    };
}

// Protokoll-Aushandlung (draft-webtrans-http3 §3.3): wir sprechen echo-v2/echo-v1 — die Angebotsliste
// des Clients ist nach Präferenz sortiert, also gewinnt sein bestes von uns unterstütztes Angebot.
static string? SelectWebTransportProtocol(Http3Request request, IReadOnlyList<string> offered)
{
    Console.WriteLine($"  → WT-Available-Protocols: {string.Join(", ", offered)}");
    return offered.FirstOrDefault(p => p is "echo-v2" or "echo-v1");
}

static Http3Response Handle(Http3Request request)
{
    Console.WriteLine($"  → {request.Method} {request.Path}  (:authority={request.Authority}"
                      + (request.Body.Length > 0 ? $", Rumpf {request.Body.Length} Bytes" : "") + ")");

    // GET /big: ~300 KB deterministischer Rumpf — Spielwiese für Priorisierung (RFC 9218) und Transfers.
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

    // GET /hints: 103 Early Hints (Interim-Response, RFC 9110 §15.2.2) vor der finalen Antwort und
    // eine Trailer-Sektion mit Prüfsumme danach (RFC 9114 §4.1: HEADERS(1xx) → HEADERS → DATA → HEADERS).
    if (request.Path == "/hints")
    {
        byte[] hintsBody = Encoding.UTF8.GetBytes("<html><head><title>Early Hints</title></head><body>Rumpf nach 103.</body></html>");
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

    // POST /echo: den Request-Rumpf byte-genau zurückspiegeln (RFC 9114 §4.1 — Content in DATA-Frames).
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
          <h1>Hallo von einem selbstgebauten HTTP/3-Server!</h1>
          <p>Du hast <code>{request.Method} {request.Path}</code> angefragt.</p>
          <p>QUIC + TLS 1.3 + QPACK + HTTP/3 — alles from scratch auf .NET, nur BCL.</p>
        </body></html>
        """;
    return new Http3Response
    {
        Status = 200,
        Headers = [new HeaderField("content-type", "text/html; charset=utf-8"), new HeaderField("server", "http3-from-scratch")],
        Body = Encoding.UTF8.GetBytes(html),
    };
}

// Eine Serververbindung samt aktueller Peer-Adresse (die sich bei Migration ändern kann).
sealed class ServerConn(Http3ServerConnection connection, EndPoint endpoint)
{
    public Http3ServerConnection Connection { get; } = connection;
    public EndPoint Endpoint { get; set; } = endpoint;
    public bool PathAnnounced { get; set; }
    public bool GoAwayAnnounced { get; set; } // GOAWAY bereits gesendet (Graceful-Shutdown-Demo)
}
