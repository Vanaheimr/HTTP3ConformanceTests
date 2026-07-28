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

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Qlog;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

// ---------------------------------------------------------------------------------------------
// H3Get: a real HTTP/3 client, from scratch. Default: GET; --post=<text> sends a POST with a
// body instead. Further demos: --cancel (request cancellation mid-download),
// --goaway (observe graceful shutdown, against `H3Server --goaway`), --zerortt/--resume,
// --key-update, --migrate, --rotate-cid, --qpack-dynamic, --mlkem/--x448/--chacha20, --hold=<s>
// and artificial packet loss (--loss=N) as loss-recovery proof (RFC 9002). The server
// certificate is validated by default (chain against the system roots + hostname); -k/--insecure
// skips that like curl (only for self-signed test servers, e.g. the local H3Server).
// ---------------------------------------------------------------------------------------------

string host = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "cloudflare-quic.com";
string path = args.Where(a => !a.StartsWith('-')).Skip(1).FirstOrDefault() ?? "/";
int port = ParseIntArg(args, "--port=", 443);
int lossPercent = ParseLoss(args);
bool insecure = args.Contains("-k") || args.Contains("--insecure");
bool keyUpdate = args.Contains("--key-update");
bool rotateCid = args.Contains("--rotate-cid");
bool migrate = args.Contains("--migrate");
// --post=<text>: send a POST with a body instead of a GET (request body as a DATA frame, RFC 9114 §4.1).
string? postBody = args.FirstOrDefault(a => a.StartsWith("--post=", StringComparison.Ordinal))?["--post=".Length..];
var rng = new Random(1234);
int dropped = 0;

// --interop: run the client interop matrix against foreign public HTTP/3 servers (fresh connection
// each, FULL certificate chain). One command, repeatable at any time — see INTEROP.md.
if (args.Contains("--interop"))
    return RunInteropMatrix();

Console.WriteLine($"== HTTP/3 from Scratch — GET https://{host}{path}"
                  + (lossPercent > 0 ? $" (artificial packet loss {lossPercent} %)" : "") + " ==\n");

using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1500 };
// Windows quirk: sending to a (still) dead port makes an ICMP "port unreachable" cripple the UDP socket
// with ConnectionReset. SIO_UDP_CONNRESET=false turns that off (packets are silently dropped instead of
// disturbing the socket) — more robust in case the server is briefly unreachable.
try { socket.IOControl(unchecked((int)0x9800000C), [0, 0, 0, 0], null); } catch { /* non-Windows: ignore */ }
var remote = new IPEndPoint(Dns.GetHostAddresses(host).First(a => a.AddressFamily == AddressFamily.InterNetwork), port);

// Flow-control windows: --small forces small windows (demonstrates MAX_STREAM_DATA/MAX_DATA,
// phase 4), otherwise generous (reduces head-of-line blocking under packet loss).
bool small = args.Contains("--small");
var transportParams = small
    ? new TransportParameters { InitialMaxDataValue = 49152, InitialMaxStreamDataBidiLocalValue = 32768, InitialMaxStreamDataUniValue = 32768 }
    : new TransportParameters();
if (rotateCid)
    transportParams.ActiveConnectionIdLimitValue = 8; // allow the server to issue more connection IDs

var validation = insecure ? CertificateValidationOptions.Insecure : CertificateValidationOptions.Default;
// --qpack-dynamic: enable the dynamic QPACK table (RFC 9204) (only against our own server;
// against Cloudflare it stays static/interop-safe by default).
ulong qpackCapacity = args.Contains("--qpack-dynamic") ? 4096u : 0u;
// --chacha20: offer only TLS_CHACHA20_POLY1305_SHA256 ⇒ the server must pick ChaCha20-Poly1305.
IReadOnlyList<CipherSuite>? cipherSuites =
    args.Contains("--chacha20") ? [CipherSuite.ChaCha20Poly1305Sha256] : null;
// --x448 / --mlkem: force a specific named group (x448 or the PQ hybrid X25519MLKEM768).
IReadOnlyList<NamedGroup>? keyExchangeGroups =
    args.Contains("--mlkem") ? [NamedGroup.X25519MlKem768]
    : args.Contains("--x448") ? [NamedGroup.X448]
    : null;
bool wantWebTransport = args.Contains("--webtransport");
// --keylog[=<path>]: writes the TLS secrets in NSS key log format so Wireshark can decrypt our own
// QUIC packets (RFC 8446 §7.1 secrets). Without a path the SSLKEYLOGFILE convention applies.
// DEBUGGING ONLY — anyone holding the file can decrypt the recorded traffic.
KeyLog? keyLog = ParseKeyLog(args);
// --qlog[=<path>]: structured connection log (qlog, JSON-SEQ) for https://qvis.quictools.info
QlogWriter? qlog = ParseQlog(args, isServer: false);
if (qlog is not null)
    Console.WriteLine("  qlog active — load the .sqlog file into qvis.");
if (keyLog is not null)
    Console.WriteLine("  Key log active (NSS format) — Wireshark can decrypt this connection.\n");
using var http3 = new Http3ClientConnection(host, transportParams, validation, qpackCapacity, cipherSuites, keyExchangeGroups,
                                            enableDatagrams: args.Contains("--datagrams") || wantWebTransport, // RFC 9297/9221
                                            webTransportMaxSessions: wantWebTransport ? 4u : 0u, // draft-webtrans-http3
                                            keyLog: keyLog, qlog: qlog);
http3.Start();

try
{
    for (int round = 0; round < 12 && !http3.HandshakeConfirmed; round++)
        Exchange();
}
catch (CertificateValidationException ex)
{
    Console.WriteLine($"✗ Certificate validation failed: {ex.Message}");
    Console.WriteLine("  (Use -k/--insecure for self-signed test servers.)");
    return 1;
}
if (!http3.HandshakeConfirmed) { Console.WriteLine("Handshake failed."); return 1; }
Console.WriteLine($"✓ Handshake completed (group {http3.Quic.NegotiatedGroup}, suite {http3.Quic.NegotiatedCipherSuite})"
                  + (http3.RetryHandled ? " after Retry (address validation)" : "")
                  + $"{(lossPercent > 0 ? $" despite {dropped} dropped datagrams" : "")}.");
Console.WriteLine($"  Server certificate: {http3.Quic.ServerCertificate?.Subject} "
                  + $"(key OID {http3.Quic.ServerCertificate?.PublicKey.Oid.Value}) — "
                  + (insecure ? "signature verified, chain/hostname skipped (-k)"
                             : "signature + chain + hostname verified") + "\n");

http3.InitializeHttp3();
// Briefly shuttle datagrams so the server's SETTINGS arrive (learn its capacity).
for (int round = 0; round < 3; round++)
    Exchange();
if (http3.ServerMaxFieldSectionSize is { } maxFieldSection)
    Console.WriteLine($"  Server limit: MAX_FIELD_SECTION_SIZE = {maxFieldSection} bytes (RFC 9114 §4.2.2) — we do not send larger header sections.");

Http3Request request = postBody is not null
    ? Http3Request.Post(host, path, System.Text.Encoding.UTF8.GetBytes(postBody), "text/plain; charset=utf-8")
    : Http3Request.Get(host, path);
ulong requestStream = http3.SendRequest(request);
Console.WriteLine($"→ {request.Method} sent (stream {requestStream})"
                  + (postBody is not null ? $" — body {request.Body.Length} bytes as a DATA frame" : "")
                  + (qpackCapacity > 0 ? " (QPACK dynamic table active)" : "") + "\n");

// Optional: request cancellation (RFC 9114 §4.1.1) — abort the running download mid-transfer
// (RESET_STREAM + STOP_SENDING with H3_REQUEST_CANCELLED) and prove that the CONNECTION
// lives on: a second GET over the same connection delivers the full response.
if (args.Contains("--cancel"))
{
    for (int round = 0; round < 2; round++)
        Exchange(); // let part of the response arrive (slow start ⇒ far from everything)
    http3.CancelRequest(requestStream);
    Console.WriteLine("→ Request cancelled mid-download (RESET_STREAM + STOP_SENDING, H3_REQUEST_CANCELLED) …");
    for (int round = 0; round < 6; round++)
        Exchange();
    if (http3.IsRequestCancelled(requestStream))
        Console.WriteLine("  Cancellation effective"
                          + (http3.RequestResetErrorCode(requestStream) is { } rc
                             ? $" — the server reset its response side (code 0x{rc:x})."
                             : " — the server stopped its send flow."));
    else
        Console.WriteLine("  Response was already complete — cancellation ignored per RFC 9114 §4.1.1 (response remains usable).");

    ulong secondStream = http3.SendRequest(request);
    Http3Response? secondResponse = null;
    for (int round = 0; round < 120 && secondResponse is null; round++)
    {
        Exchange();
        http3.TryGetResponse(secondStream, out secondResponse);
    }
    if (secondResponse is null) { Console.WriteLine("✗ Second GET after the cancellation failed."); return 1; }
    Console.WriteLine($"HTTP/3 {secondResponse.Status} ({secondResponse.Body.Length} bytes) over the SAME connection after the cancellation.");
    Console.WriteLine("✓✓ Request cancellation successful — the connection lives on (second GET ok).");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return 0;
}

Http3Response? response = null;
for (int round = 0; round < 120; round++)
{
    Exchange();
    if (http3.TryGetResponse(requestStream, out response) && response is not null)
        break;
}

Console.WriteLine("== Response ==");
if (response is null) { Console.WriteLine("No complete response received."); return 1; }

// Make interim responses (1xx, RFC 9114 §4.1) and the trailer section visible, if present.
foreach (var interim in response.InterimResponses)
    Console.WriteLine($"HTTP/3 {interim.Status} (interim) — {string.Join(", ", interim.Headers.Select(h => $"{h.Name}: {h.Value}"))}");
Console.WriteLine($"HTTP/3 {response.Status}  ({response.GetHeader("content-type")})");
if (response.Trailers.Count > 0)
    Console.WriteLine($"Trailers: {string.Join(", ", response.Trailers.Select(h => $"{h.Name}: {h.Value}"))}");
if (postBody is not null)
    Console.WriteLine($"Body ({response.Body.Length} bytes): {(response.BodyText.Length <= 200 ? response.BodyText : response.BodyText[..200] + "…")}");
else
    Console.WriteLine($"Body: {response.Body.Length} bytes, title: {ExtractTitle(response.BodyText)}");
Console.WriteLine($"\n✓✓ HTTP/3 {request.Method} successful — status {response.Status}"
                  + (lossPercent > 0 ? $", {dropped} datagrams dropped and bridged via retransmission." : "."));
if (qpackCapacity > 0)
    Console.WriteLine($"  QPACK dynamic table: {http3.QpackEncoderInsertCount} request inserts, "
                      + $"{http3.QpackDecoderInsertCount} response inserts received.");

// Optional: session resumption (RFC 8446 §2.2) or 0-RTT early data (--zerortt). First collect the
// NewSessionTicket of the first connection, then build a fresh connection with the ticket;
// with --zerortt the HTTP/3 request goes out as early data, before the handshake completes.
bool zeroRtt = args.Contains("--zerortt");
if (args.Contains("--resume") || zeroRtt)
{
    Console.WriteLine(zeroRtt ? "\n== 0-RTT (early data) ==" : "\n== Session resumption ==");
    http3.KeepAliveInterval = TimeSpan.FromMilliseconds(200);
    var ticketWait = Stopwatch.StartNew();
    while (ticketWait.Elapsed.TotalSeconds < 4 && http3.NewSessionTickets.Count == 0)
        Exchange();

    Console.WriteLine($"  (Diagnostics: {http3.Quic.NewSessionTicketMessagesSeen} NST message(s) received, "
                      + $"{http3.NewSessionTickets.Count} usable as tickets.)");
    if (http3.NewSessionTickets.Count == 0)
    {
        Console.WriteLine("✗ No NewSessionTicket received — resumption not possible.");
        http3.Close();
        foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
        return 1;
    }

    ResumptionTicket ticket = http3.NewSessionTickets[0];
    Console.WriteLine($"→ {http3.NewSessionTickets.Count} ticket(s) received (identity {ticket.Identity.Length} B). New connection with PSK …");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);

    using var socket2 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1500 };
    using var resumed = new Http3ClientConnection(host, new TransportParameters(), validation, qpackCapacity, cipherSuites, keyExchangeGroups, ticket);
    resumed.Start();

    ulong resumeStream;
    if (zeroRtt)
    {
        // 0-RTT: queue the request BEFORE the handshake ⇒ it goes out as early data (long header 0x01),
        // without waiting for ServerHello/Finished (0 round trips until the request).
        resumed.InitializeHttp3();
        resumeStream = resumed.SendRequest(Http3Request.Get(host, path));
        Console.WriteLine("→ HTTP/3 GET sent as 0-RTT early data (before handshake completion).");
    }
    else
    {
        for (int round = 0; round < 12 && !resumed.HandshakeConfirmed; round++)
            ExchangeWith(resumed, socket2);
        if (!resumed.HandshakeConfirmed) { Console.WriteLine("✗ Resumption handshake failed."); return 1; }
        Console.WriteLine(resumed.ResumptionAccepted
            ? "✓ Handshake completed via resumption — PSK accepted, NO certificate sent."
            : "○ Server declined the resumption — regular handshake with certificate.");
        resumed.InitializeHttp3();
        for (int round = 0; round < 3; round++)
            ExchangeWith(resumed, socket2);
        resumeStream = resumed.SendRequest(Http3Request.Get(host, path));
    }

    Http3Response? resumeResponse = null;
    for (int round = 0; round < 120 && resumeResponse is null; round++)
    {
        ExchangeWith(resumed, socket2);
        resumed.TryGetResponse(resumeStream, out resumeResponse);
    }
    if (resumeResponse is null) { Console.WriteLine("✗ GET over the resumed connection failed."); return 1; }

    if (zeroRtt)
        Console.WriteLine(resumed.EarlyDataAccepted
            ? "✓ 0-RTT ACCEPTED — the request ran as early data (no round trip until the request)."
            : "○ Server declined 0-RTT — the request was answered regularly over 1-RTT.");
    else
        Console.WriteLine(resumed.ResumptionAccepted
            ? "  (via resumption, no certificate)" : "  (regular handshake)");
    Console.WriteLine($"HTTP/3 {resumeResponse.Status} ({resumeResponse.Body.Length} bytes) over the {(resumed.ResumptionAccepted ? "resumed" : "new")} connection.");
    Console.WriteLine($"✓✓ Second GET after {(zeroRtt ? "0-RTT early data" : "session resumption")} successful — status {resumeResponse.Status}.");

    resumed.Close();
    foreach (byte[] dg in resumed.GetDatagramsToSend()) socket2.SendTo(dg, remote);
    return 0;
}

// Optional: WebTransport (draft-webtrans-http3, only against our own server): session via Extended
// CONNECT (:protocol=webtransport), then datagram + uni stream + bidi stream (with echo) + session end.
if (args.Contains("--webtransport"))
{
    Console.WriteLine("\n== WebTransport over HTTP/3 (draft-ietf-webtrans-http3) ==");
    for (int round = 0; round < 20 && !http3.ServerSupportsWebTransport; round++)
        Exchange();
    if (!http3.ServerSupportsWebTransport) { Console.WriteLine("✗ Server does not support WebTransport."); return 1; }
    Console.WriteLine("→ Server support detected (WT_MAX_SESSIONS > 0, Extended CONNECT, datagrams).");

    // Protocol negotiation (draft §3.3): offers in preference order; the server picks one.
    ulong wtStream = http3.ConnectWebTransport(host, "/wt",
        availableProtocols: ["echo-v3", "echo-v2", "echo-v1"]);
    org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport.WebTransportSession? wt = null;
    for (int round = 0; round < 40 && wt is null; round++) { Exchange(); http3.TryGetWebTransportSession(wtStream, out wt); }
    if (wt is null) { Console.WriteLine($"✗ Session failed (status {http3.WebTransportConnectStatus(wtStream)})."); return 1; }
    Console.WriteLine($"→ Session {wt.SessionId} established (flow control: {(wt.FlowControlEnabled ? "on" : "off")}, " +
                      $"WT-Protocol: {wt.NegotiatedProtocol ?? "none"}).");

    // Keying-material exporter (draft §4.7 / RFC 8446 §7.5): must match the server byte for byte.
    byte[] ekm = wt.ExportKeyingMaterial("demo-export", [1, 2, 3], 16);
    Console.WriteLine($"→ Keying-material export (label \"demo-export\"): {Convert.ToHexString(ekm).ToLowerInvariant()}");

    // Datagram.
    wt.SendDatagram(System.Text.Encoding.UTF8.GetBytes("WT datagram!"));
    byte[]? dg = null;
    for (int round = 0; round < 40 && dg is null; round++) { Exchange(); wt.TryReceiveDatagram(out dg); }
    Console.WriteLine(dg is not null ? $"← Datagram echo: \"{System.Text.Encoding.UTF8.GetString(dg)}\"" : "○ (no datagram echo — unreliable)");

    // Unidirectional stream (client → server).
    var uni = wt.OpenUnidirectionalStream();
    uni!.Write(System.Text.Encoding.UTF8.GetBytes("uni-hello")); uni.Finish();
    Console.WriteLine("→ Unidirectional WebTransport stream sent (0x54 ‖ session ID ‖ data).");

    // Bidirectional stream with echo (client → server → client).
    var bidi = wt.OpenBidirectionalStream();
    bidi!.Write(System.Text.Encoding.UTF8.GetBytes("bidi-ping")); bidi.Finish();
    var reply = new List<byte>();
    for (int round = 0; round < 60 && !bidi.IsReceiveComplete; round++) { Exchange(); reply.AddRange(bidi.Read()); }
    reply.AddRange(bidi.Read());
    Console.WriteLine($"← Bidi echo: \"{System.Text.Encoding.UTF8.GetString(reply.ToArray())}\" (WT_STREAM 0x41)");

    wt.Close(0, "done");
    for (int round = 0; round < 10; round++) Exchange();
    Console.WriteLine($"✓✓ WebTransport successful — session closed (IsClosed={wt.IsClosed}).");
    http3.Close();
    foreach (byte[] d in http3.GetDatagramsToSend()) socket.SendTo(d, remote);
    return 0;
}

// Optional: HTTP datagrams (RFC 9297) over QUIC DATAGRAM frames (RFC 9221, only against our own
// server): unreliable messages alongside the byte stream of an Extended-CONNECT tunnel —
// the foundation of MASQUE/connect-udp and WebTransport.
if (args.Contains("--datagrams"))
{
    Console.WriteLine("\n== HTTP datagrams (RFC 9297/9221) ==");
    for (int round = 0; round < 20 && !http3.DatagramsNegotiated; round++)
        Exchange();
    if (!http3.DatagramsNegotiated) { Console.WriteLine("✗ Datagrams not negotiated."); return 1; }
    Console.WriteLine($"→ Negotiated: SETTINGS_H3_DATAGRAM = 1 on both sides, max_datagram_frame_size = {http3.Quic.PeerMaxDatagramFrameSize}.");

    ulong dgStream = http3.SendExtendedConnect(host, "/", "datagram-echo");
    Http3Tunnel? dgTunnel = null;
    int dgStatus = 0;
    for (int round = 0; round < 40 && dgTunnel is null && dgStatus == 0; round++)
    {
        Exchange();
        http3.TryGetConnectResponse(dgStream, out dgStatus, out _, out dgTunnel);
    }
    if (dgTunnel is null) { Console.WriteLine($"✗ CONNECT failed (status {dgStatus})."); return 1; }
    Console.WriteLine($"→ CONNECT :protocol=datagram-echo accepted (status {dgStatus}).");

    int echoed = 0;
    for (int i = 1; i <= 3; i++)
    {
        byte[] ping = System.Text.Encoding.UTF8.GetBytes($"Datagram #{i} over QUIC!");
        if (!dgTunnel.TrySendDatagram(ping)) { Console.WriteLine("✗ Send refused."); return 1; }
        byte[]? pong = null;
        for (int round = 0; round < 40 && pong is null; round++)
        {
            Exchange();
            dgTunnel.TryReceiveDatagram(out pong);
        }
        if (pong is null) { Console.WriteLine($"✗ No echo for datagram #{i} (unreliable — unexpected here locally)."); return 1; }
        Console.WriteLine($"← Echo #{i}: \"{System.Text.Encoding.UTF8.GetString(pong)}\" ({pong.Length} bytes, in one DATAGRAM frame)");
        echoed++;
    }
    Console.WriteLine($"✓✓ {echoed}/3 HTTP datagrams echoed — RFC 9297 (quarter stream ID) over RFC 9221 (DATAGRAM frames).");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return 0;
}

// Optional: WebSocket over HTTP/3 (RFC 9220, only against our own server): Extended CONNECT with
// :protocol=websocket (RFC 8441), then RFC 6455 frames through the tunnel (DATA frames, RFC 9114 §4.4).
if (args.Contains("--websocket"))
{
    Console.WriteLine("\n== WebSocket over HTTP/3 (RFC 9220) ==");
    for (int round = 0; round < 20 && !http3.ServerEnablesConnectProtocol; round++)
        Exchange();
    if (!http3.ServerEnablesConnectProtocol) { Console.WriteLine("✗ Server does not allow Extended CONNECT."); return 1; }
    Console.WriteLine("→ SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 received — Extended CONNECT allowed.");

    ulong wsStream = http3.SendExtendedConnect(host, "/chat", "websocket",
        [new org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack.HeaderField("sec-websocket-version", "13")]);
    int wsStatus = 0;
    Http3Tunnel? tunnel = null;
    for (int round = 0; round < 40 && tunnel is null && wsStatus == 0; round++)
    {
        Exchange();
        http3.TryGetConnectResponse(wsStream, out wsStatus, out _, out tunnel);
    }
    if (tunnel is null) { Console.WriteLine($"✗ CONNECT failed (status {wsStatus})."); return 1; }
    Console.WriteLine($"→ CONNECT :protocol=websocket accepted (status {wsStatus}) — stream {wsStream} is now the tunnel.");

    var ws = new WebSocketConnection(tunnel, WebSocketRole.Client);
    _ = ws.SendTextAsync("Hello WebSocket over HTTP/3 — from scratch!", CancellationToken.None);
    var receive = ws.ReceiveAsync(CancellationToken.None);
    for (int round = 0; round < 100 && !receive.IsCompleted; round++)
        Exchange();
    if (!receive.IsCompleted || receive.Result is not { } wsEcho) { Console.WriteLine("✗ No WebSocket echo received."); return 1; }
    Console.WriteLine($"← Echo: \"{System.Text.Encoding.UTF8.GetString(wsEcho.Payload)}\"");

    _ = ws.CloseAsync(1000, "done", CancellationToken.None);
    var closing = ws.ReceiveAsync(CancellationToken.None);
    for (int round = 0; round < 40 && !closing.IsCompleted; round++)
        Exchange();
    Console.WriteLine(closing.IsCompleted && closing.Result is null
        ? "✓ Close handshake performed (RFC 6455 §5.5.1) — tunnel ended in an orderly fashion."
        : "✗ Close handshake not performed.");
    Console.WriteLine("✓✓ WebSocket over HTTP/3 successful — RFC 9220 + RFC 8441 + RFC 6455 over our stack.");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return 0;
}

// Optional: demonstrate prioritization (RFC 9218) — only meaningful against our own server (route /big):
// two competing downloads, the SECOND with `priority: u=0` (urgent) — the server serves it
// first even though it was requested later. Then the same with PRIORITY_UPDATE reprioritization.
if (args.Contains("--priorities"))
{
    Console.WriteLine("\n== Prioritization (RFC 9218) ==");
    ulong slow = http3.SendRequest(Http3Request.Get(host, "/big"));                                       // u=3 (default)
    ulong fast = http3.SendRequest(Http3Request.Get(host, "/big") with { Priority = new Http3Priority(0, false) }); // u=0
    Console.WriteLine($"→ Two GET /big: stream {slow} (default u=3), then stream {fast} (priority: u=0)");

    ulong? firstDone = null;
    Http3Response? slowResp = null, fastResp = null;
    for (int round = 0; round < 400 && (slowResp is null || fastResp is null); round++)
    {
        Exchange();
        if (slowResp is null && http3.TryGetResponse(slow, out slowResp) && firstDone is null) firstDone = slow;
        if (fastResp is null && http3.TryGetResponse(fast, out fastResp) && firstDone is null) firstDone = fast;
    }
    if (slowResp is null || fastResp is null) { Console.WriteLine("✗ Responses incomplete."); return 1; }
    Console.WriteLine(firstDone == fast
        ? $"✓ The more urgent download (u=0, stream {fast}) arrived FIRST — although requested later."
        : "✗ Expected the u=0 download to finish first!");

    // Reprioritization (RFC 9218 §6/§7): start a "prefetch" with u=0, then demote it via
    // PRIORITY_UPDATE to u=7 (background) — the default download overtakes it.
    ulong prefetch = http3.SendRequest(Http3Request.Get(host, "/big") with { Priority = new Http3Priority(0, false) });
    ulong normal = http3.SendRequest(Http3Request.Get(host, "/big"));
    http3.SendPriorityUpdate(prefetch, new Http3Priority(7, false));
    Console.WriteLine($"→ Reprioritization: stream {prefetch} (header u=0) demoted to u=7 via PRIORITY_UPDATE; stream {normal} (u=3)");

    firstDone = null;
    Http3Response? prefetchResp = null, normalResp = null;
    for (int round = 0; round < 400 && (prefetchResp is null || normalResp is null); round++)
    {
        Exchange();
        if (prefetchResp is null && http3.TryGetResponse(prefetch, out prefetchResp) && firstDone is null) firstDone = prefetch;
        if (normalResp is null && http3.TryGetResponse(normal, out normalResp) && firstDone is null) firstDone = normal;
    }
    if (prefetchResp is null || normalResp is null) { Console.WriteLine("✗ Responses incomplete."); return 1; }
    Console.WriteLine(firstDone == normal
        ? $"✓ The PRIORITY_UPDATE (u=7) overrode the header (u=0) — stream {normal} overtook the demoted prefetch."
        : "✗ Expected the PRIORITY_UPDATE to demote the prefetch!");
    Console.WriteLine($"✓✓ RFC 9218 prioritization successful ({slowResp.Body.Length} bytes per download, 4 downloads).");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return firstDone == normal ? 0 : 1;
}

// Optional: observe GOAWAY / graceful shutdown (RFC 9114 §5.2, only against `H3Server --goaway`):
// the server announces the teardown via GOAWAY after the response; new requests are then forbidden,
// and the connection ends decently with H3_NO_ERROR (CONNECTION_CLOSE type 0x1d).
if (args.Contains("--goaway"))
{
    Console.WriteLine("\n== GOAWAY / graceful shutdown ==");
    for (int round = 0; round < 40 && http3.GoAwayStreamId is null && http3.PeerCloseFrame is null; round++)
        Exchange();

    if (http3.GoAwayStreamId is not { } goAwayId)
    {
        Console.WriteLine("✗ No GOAWAY received.");
        return 1;
    }
    Console.WriteLine($"→ GOAWAY received: limit stream ID {goAwayId} — no new requests on this connection.");
    try
    {
        http3.SendRequest(Http3Request.Get(host, path));
        Console.WriteLine("✗ The new request should have been refused!");
        return 1;
    }
    catch (InvalidOperationException)
    {
        Console.WriteLine("✓ New request correctly refused (RFC 9114 §5.2 MUST NOT).");
    }

    for (int round = 0; round < 40 && http3.PeerCloseFrame is null; round++)
        Exchange();
    if (http3.PeerCloseFrame is not { } close)
    {
        Console.WriteLine("✗ No CONNECTION_CLOSE from the server received.");
        return 1;
    }
    Console.WriteLine($"✓✓ Server closed decently: CONNECTION_CLOSE ({(close.IsApplicationError ? "application" : "transport")}) "
                      + $"code 0x{close.ErrorCode:x}{(close.ErrorCode == Http3Error.NoError ? " = H3_NO_ERROR" : "")}.");
    return 0;
}

// Optional: 1-RTT key update (RFC 9001 §6) and a second GET under the rotated keys.
if (keyUpdate)
{
    http3.Quic.InitiateKeyUpdate();
    Console.WriteLine($"\n== Key update == (key phase {(http3.Quic.CurrentKeyPhase ? 1 : 0)})");
    ulong stream2 = http3.SendRequest(Http3Request.Get(host, path));
    Http3Response? response2 = null;
    for (int round = 0; round < 120; round++)
    {
        Exchange();
        if (http3.TryGetResponse(stream2, out response2) && response2 is not null)
            break;
    }
    if (response2 is null) { Console.WriteLine("Second GET after key update failed."); return 1; }
    Console.WriteLine($"HTTP/3 {response2.Status} ({response2.Body.Length} bytes) under new keys"
                      + $" — key phase {(http3.Quic.CurrentKeyPhase ? 1 : 0)}, {http3.Quic.KeyUpdateCount} rotations.");
    Console.WriteLine("✓✓ Second GET after key update successful.");
}

// Optional: connection ID rotation (RFC 9000 §5.1) — switch the DCID to a CID issued by the server.
if (rotateCid)
{
    for (int round = 0; round < 6; round++) // give the server time to send NEW_CONNECTION_ID
        Exchange();
    Console.WriteLine($"\n== Connection ID rotation == (known server CIDs: {http3.Quic.RemoteConnectionIdCount})");
    if (http3.Quic.RotateDestinationConnectionId())
    {
        Console.WriteLine($"→ DCID switched to {http3.Quic.DestinationConnectionId}; second GET under the new CID …");
        ulong stream3 = http3.SendRequest(Http3Request.Get(host, path));
        Http3Response? response3 = null;
        for (int round = 0; round < 120; round++)
        {
            Exchange();
            if (http3.TryGetResponse(stream3, out response3) && response3 is not null)
                break;
        }
        if (response3 is null) { Console.WriteLine("Second GET after CID rotation failed."); return 1; }
        Console.WriteLine($"HTTP/3 {response3.Status} ({response3.Body.Length} bytes) under the new connection ID.");
        Console.WriteLine("✓✓ Second GET after connection ID rotation successful.");
    }
    else
        Console.WriteLine("Server offered no additional connection ID — no rotation possible.");
}

// Optional: connection migration (RFC 9000 §9) — switch the local UDP port and fetch another GET
// over the new path. The server demultiplexes via the connection ID and validates the new path.
if (migrate)
{
    using var migratedSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1500 };
    migratedSocket.Bind(new IPEndPoint(System.Net.IPAddress.Any, 0));
    Console.WriteLine($"\n== Connection migration == new local port {((IPEndPoint)migratedSocket.LocalEndPoint!).Port}; second GET over the new path …");

    ulong migStream = http3.SendRequest(Http3Request.Get(host, path));
    Http3Response? migResponse = null;
    for (int round = 0; round < 120 && migResponse is null; round++)
    {
        http3.CheckTimeouts();
        foreach (byte[] dg in http3.GetDatagramsToSend())
            migratedSocket.SendTo(dg, remote);
        byte[] buf = new byte[2048];
        for (int i = 0; i < 32; i++)
        {
            try
            {
                EndPoint f = new IPEndPoint(System.Net.IPAddress.Any, 0);
                int m = migratedSocket.ReceiveFrom(buf, ref f);
                http3.ProcessDatagram(buf.AsSpan(0, m));
            }
            catch (SocketException) { break; }
        }
        http3.TryGetResponse(migStream, out migResponse);
    }

    if (migResponse is null) { Console.WriteLine("Second GET after migration failed."); return 1; }
    Console.WriteLine($"HTTP/3 {migResponse.Status} ({migResponse.Body.Length} bytes) over the new path.");
    Console.WriteLine("✓✓ Second GET after connection migration successful (the connection survives the address change).");
}

// Optional: keep the connection idle for N seconds via keep-alive PINGs (RFC 9000 §10.1.2).
int holdSeconds = ParseIntArg(args, "--hold=", 0);
if (holdSeconds > 0)
{
    http3.KeepAliveInterval = TimeSpan.FromMilliseconds(500);
    Console.WriteLine($"\n== Keep-alive == holding the connection idle for {holdSeconds}s (PING every 500 ms) …");
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed.TotalSeconds < holdSeconds && !http3.IsIdleTimedOut)
        Exchange();
    Console.WriteLine(http3.IsIdleTimedOut
        ? "✗ Connection was closed despite keep-alive."
        : $"✓ Connection still open after {holdSeconds}s idle — idle timeout prevented via keep-alive.");
}

// Decent teardown (RFC 9000 §10.2): send CONNECTION_CLOSE with NO_ERROR.
http3.Close();
foreach (byte[] datagram in http3.GetDatagramsToSend())
    socket.SendTo(datagram, remote);
Console.WriteLine("→ Connection closed (CONNECTION_CLOSE, NO_ERROR).");
return 0;

void Exchange() => ExchangeWith(http3, socket);

void ExchangeWith(Http3ClientConnection conn, Socket sock)
{
    conn.CheckTimeouts(); // loss detection/PTO
    foreach (byte[] datagram in conn.GetDatagramsToSend())
    {
        if (Drop()) continue; // outgoing loss
        sock.SendTo(datagram, remote);
    }

    byte[] buffer = new byte[2048];
    for (int i = 0; i < 32; i++)
    {
        try
        {
            EndPoint from = new IPEndPoint(System.Net.IPAddress.Any, 0);
            int n = sock.ReceiveFrom(buffer, ref from);
            if (Drop()) continue; // incoming loss
            conn.ProcessDatagram(buffer.AsSpan(0, n));
        }
        catch (SocketException) { break; }
    }
}

bool Drop()
{
    if (lossPercent <= 0 || rng.Next(100) >= lossPercent)
        return false;
    dropped++;
    return true;
}

static int ParseLoss(string[] args)
{
    string? arg = args.FirstOrDefault(a => a.StartsWith("--loss=", StringComparison.Ordinal));
    return arg is not null && int.TryParse(arg["--loss=".Length..], out int v) ? Math.Clamp(v, 0, 90) : 0;
}

static QlogWriter? ParseQlog(string[] args, bool isServer)
{
    string? arg = args.FirstOrDefault(a => a == "--qlog" || a.StartsWith("--qlog="));
    if (arg is null)
        return null;
    string path = arg.StartsWith("--qlog=") ? arg["--qlog=".Length..] : $"h3-{DateTime.Now:yyyyMMdd-HHmmss}.sqlog";
    if (File.Exists(path))
        File.Delete(path); // a trace is one connection – do not append to an old run
    return QlogWriter.ToFile(path, isServer);
}

static KeyLog? ParseKeyLog(string[] args)
{
    string? arg = args.FirstOrDefault(a => a == "--keylog" || a.StartsWith("--keylog="));
    if (arg is null)
        return null;
    string path = arg.Length > "--keylog=".Length && arg.StartsWith("--keylog=") ? arg["--keylog=".Length..] : "";
    return path.Length > 0 ? KeyLog.ToFile(path) : KeyLog.FromEnvironment();
}

static int ParseIntArg(string[] args, string prefix, int fallback)
{
    string? arg = args.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.Ordinal));
    return arg is not null && int.TryParse(arg[prefix.Length..], out int v) ? v : fallback;
}

static string ExtractTitle(string html)
{
    int a = html.IndexOf("<title>", StringComparison.OrdinalIgnoreCase);
    int b = html.IndexOf("</title>", StringComparison.OrdinalIgnoreCase);
    return a >= 0 && b > a ? html[(a + 7)..b].Trim() : "(no title)";
}

// ---- Interop matrix (--interop) -------------------------------------------------------------
// Checks the client against several public HTTP/3 servers of different QUIC stacks — each with its
// own fresh connection and FULL certificate validation (chain + hostname). No -k. Repeatable via
// `dotnet run --project samples/H3Get -- --interop`. Details/history: INTEROP.md.
static int RunInteropMatrix()
{
    (string Host, string Stack)[] targets =
    [
        ("cloudflare-quic.com",   "quiche (Cloudflare)"),
        ("quic.nginx.org",        "nginx QUIC"),
        ("www.google.com",        "Google QUIC"),
        ("www.facebook.com",      "mvfst (Meta)"),
        ("www.litespeedtech.com", "lsquic (LiteSpeed)"),
        ("outlook.office.com",    "msquic (Microsoft)"),
        ("caddyserver.com",       "quic-go (Caddy)"),
        ("www.akamai.com",        "Akamai QUIC"),
    ];

    Console.WriteLine("== HTTP/3 from Scratch — interop matrix (full certificate validation) ==\n");
    Console.WriteLine($"{"Target",-24} {"Stack",-20} {"Group/Suite/Cert",-34} Result");
    Console.WriteLine(new string('-', 100));

    int ok = 0;
    foreach ((string targetHost, string stack) in targets)
    {
        string crypto, result;
        bool success = TryInterop(targetHost, out crypto, out result);
        if (success) ok++;
        Console.WriteLine($"{targetHost,-24} {stack,-20} {crypto,-34} {(success ? "✓ " : "✗ ")}{result}");
    }

    Console.WriteLine(new string('-', 100));
    Console.WriteLine($"\n{ok}/{targets.Length} stacks reachable (2xx/3xx = the HTTP/3 stack runs end to end; "
                      + "3xx/4xx are regular responses such as redirects/bot protection).");
    return ok > 0 ? 0 : 1;
}

// A single interop attempt: fresh connection, GET /, full cert validation. Returns the crypto profile
// and a result text; returns true as soon as an HTTP/3 status was received.
static bool TryInterop(string targetHost, out string crypto, out string result)
{
    crypto = "—";
    result = "";
    try
    {
        var addresses = Dns.GetHostAddresses(targetHost).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
        if (addresses.Length == 0) { result = "no IPv4 address"; return false; }
        var remote = new IPEndPoint(addresses[0], 443);

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 400 };
        try { socket.IOControl(unchecked((int)0x9800000C), [0, 0, 0, 0], null); } catch { /* non-Windows */ }

        using var conn = new Http3ClientConnection(targetHost, new TransportParameters(), CertificateValidationOptions.Default);
        conn.Start();

        void Pump()
        {
            conn.CheckTimeouts();
            foreach (byte[] dg in conn.GetDatagramsToSend())
                socket.SendTo(dg, remote);
            byte[] buffer = new byte[2048];
            for (int i = 0; i < 32; i++)
            {
                try
                {
                    EndPoint from = new IPEndPoint(System.Net.IPAddress.Any, 0);
                    int n = socket.ReceiveFrom(buffer, ref from);
                    conn.ProcessDatagram(buffer.AsSpan(0, n));
                }
                catch (SocketException) { break; }
            }
        }

        for (int round = 0; round < 40 && !conn.HandshakeConfirmed; round++)
            Pump();
        if (!conn.HandshakeConfirmed) { result = "handshake failed (may not offer HTTP/3)"; return false; }

        crypto = $"{conn.Quic.NegotiatedGroup}/{conn.Quic.NegotiatedCipherSuite}/{CertKind(conn.Quic.ServerCertificate?.PublicKey.Oid.Value)}";

        conn.InitializeHttp3();
        for (int round = 0; round < 3; round++) Pump();

        ulong streamId = conn.SendRequest(Http3Request.Get(targetHost, "/"));
        Http3Response? response = null;
        for (int round = 0; round < 200 && response is null; round++)
        {
            Pump();
            conn.TryGetResponse(streamId, out response);
        }
        conn.Close();
        foreach (byte[] dg in conn.GetDatagramsToSend()) socket.SendTo(dg, remote);

        if (response is null) { result = "no response"; return false; }
        result = $"HTTP/3 {response.Status}";
        return true;
    }
    catch (CertificateValidationException ex) { result = $"cert invalid: {ex.Message}"; return false; }
    catch (Exception ex) { result = $"{ex.GetType().Name}: {ex.Message}"; return false; }
}

// The public-key algorithm of a certificate from the SPKI OID (for the crypto column of the matrix).
static string CertKind(string? oid) => oid switch
{
    "1.2.840.10045.2.1"    => "ECDSA",
    "1.2.840.113549.1.1.1" => "RSA",
    "1.3.101.112"          => "Ed25519",
    "1.3.101.113"          => "Ed448",
    "2.16.840.1.101.3.4.3.17" or "2.16.840.1.101.3.4.3.18" or "2.16.840.1.101.3.4.3.19" => "ML-DSA",
    null                   => "?",
    _                      => oid,
};
