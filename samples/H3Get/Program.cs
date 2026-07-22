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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

// ---------------------------------------------------------------------------------------------
// H3Get: Ein echter HTTP/3-Client, from scratch. Standard: GET; --post=<Text> sendet stattdessen
// einen POST mit Rumpf. Weitere Demos: --cancel (Request-Cancellation mitten im Download),
// --goaway (Graceful Shutdown beobachten, gegen `H3Server --goaway`), --zerortt/--resume,
// --key-update, --migrate, --rotate-cid, --qpack-dynamic, --mlkem/--x448/--chacha20, --hold=<s>
// und künstlicher Paketverlust (--loss=N) als Loss-Recovery-Nachweis (RFC 9002). Das Server-
// zertifikat wird standardmäßig geprüft (Kette gegen die System-Roots + Hostname); -k/--insecure
// überspringt das wie curl (nur für selbstsignierte Testserver, z. B. den lokalen H3Server).
// ---------------------------------------------------------------------------------------------

string host = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "cloudflare-quic.com";
string path = args.Where(a => !a.StartsWith('-')).Skip(1).FirstOrDefault() ?? "/";
int port = ParseIntArg(args, "--port=", 443);
int lossPercent = ParseLoss(args);
bool insecure = args.Contains("-k") || args.Contains("--insecure");
bool keyUpdate = args.Contains("--key-update");
bool rotateCid = args.Contains("--rotate-cid");
bool migrate = args.Contains("--migrate");
// --post=<Text>: statt GET einen POST mit Rumpf senden (Request-Body als DATA-Frame, RFC 9114 §4.1).
string? postBody = args.FirstOrDefault(a => a.StartsWith("--post=", StringComparison.Ordinal))?["--post=".Length..];
var rng = new Random(1234);
int dropped = 0;

Console.WriteLine($"== HTTP/3 from Scratch — GET https://{host}{path}"
                  + (lossPercent > 0 ? $" (künstlicher Paketverlust {lossPercent} %)" : "") + " ==\n");

using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1500 };
// Windows-Eigenheit: Sendet man an einen (noch) toten Port, meldet ein ICMP „Port Unreachable" den UDP-Socket
// sonst mit ConnectionReset lahm. SIO_UDP_CONNRESET=false schaltet das ab (Pakete werden still verworfen statt
// den Socket zu stören) – robuster, falls der Server kurz nicht erreichbar ist.
try { socket.IOControl(unchecked((int)0x9800000C), [0, 0, 0, 0], null); } catch { /* nicht-Windows: ignorieren */ }
var remote = new IPEndPoint(Dns.GetHostAddresses(host).First(a => a.AddressFamily == AddressFamily.InterNetwork), port);

// Flow-Control-Fenster: mit --small kleine Fenster erzwingen (demonstriert MAX_STREAM_DATA/MAX_DATA,
// Phase 4), sonst großzügig (reduziert Head-of-Line-Blocking bei Paketverlust).
bool small = args.Contains("--small");
var transportParams = small
    ? new TransportParameters { InitialMaxDataValue = 49152, InitialMaxStreamDataBidiLocalValue = 32768, InitialMaxStreamDataUniValue = 32768 }
    : new TransportParameters();
if (rotateCid)
    transportParams.ActiveConnectionIdLimitValue = 8; // dem Server erlauben, mehr Connection IDs auszugeben

var validation = insecure ? CertificateValidationOptions.Insecure : CertificateValidationOptions.Default;
// --qpack-dynamic: die dynamische QPACK-Tabelle (RFC 9204) aktivieren (nur gegen unseren eigenen Server;
// gegen Cloudflare bleibt es standardmäßig statisch/interop-sicher).
ulong qpackCapacity = args.Contains("--qpack-dynamic") ? 4096u : 0u;
// --chacha20: nur TLS_CHACHA20_POLY1305_SHA256 anbieten ⇒ der Server muss ChaCha20-Poly1305 wählen.
IReadOnlyList<CipherSuite>? cipherSuites =
    args.Contains("--chacha20") ? [CipherSuite.ChaCha20Poly1305Sha256] : null;
// --x448 / --mlkem: eine bestimmte Named Group erzwingen (x448 bzw. den PQ-Hybrid X25519MLKEM768).
IReadOnlyList<NamedGroup>? keyExchangeGroups =
    args.Contains("--mlkem") ? [NamedGroup.X25519MlKem768]
    : args.Contains("--x448") ? [NamedGroup.X448]
    : null;
bool wantWebTransport = args.Contains("--webtransport");
using var http3 = new Http3ClientConnection(host, transportParams, validation, qpackCapacity, cipherSuites, keyExchangeGroups,
                                            enableDatagrams: args.Contains("--datagrams") || wantWebTransport, // RFC 9297/9221
                                            webTransportMaxSessions: wantWebTransport ? 4u : 0u); // draft-webtrans-http3
http3.Start();

try
{
    for (int round = 0; round < 12 && !http3.HandshakeConfirmed; round++)
        Exchange();
}
catch (CertificateValidationException ex)
{
    Console.WriteLine($"✗ Zertifikatsprüfung fehlgeschlagen: {ex.Message}");
    Console.WriteLine("  (Für selbstsignierte Testserver -k/--insecure verwenden.)");
    return 1;
}
if (!http3.HandshakeConfirmed) { Console.WriteLine("Handshake fehlgeschlagen."); return 1; }
Console.WriteLine($"✓ Handshake abgeschlossen (Gruppe {http3.Quic.NegotiatedGroup}, Suite {http3.Quic.NegotiatedCipherSuite})"
                  + (http3.RetryHandled ? " nach Retry (Adressvalidierung)" : "")
                  + $"{(lossPercent > 0 ? $" trotz {dropped} verworfenen Datagrammen" : "")}.");
Console.WriteLine($"  Serverzertifikat: {http3.Quic.ServerCertificate?.Subject} "
                  + $"(Schlüssel-OID {http3.Quic.ServerCertificate?.PublicKey.Oid.Value}) — "
                  + (insecure ? "Signatur geprüft, Kette/Hostname übersprungen (-k)"
                             : "Signatur + Kette + Hostname geprüft") + "\n");

http3.InitializeHttp3();
// Kurz Datagramme pendeln lassen, damit die SETTINGS des Servers ankommen (Kapazität lernen).
for (int round = 0; round < 3; round++)
    Exchange();
if (http3.ServerMaxFieldSectionSize is { } maxFieldSection)
    Console.WriteLine($"  Server-Limit: MAX_FIELD_SECTION_SIZE = {maxFieldSection} Bytes (RFC 9114 §4.2.2) — größere Header-Sektionen senden wir nicht.");

Http3Request request = postBody is not null
    ? Http3Request.Post(host, path, System.Text.Encoding.UTF8.GetBytes(postBody), "text/plain; charset=utf-8")
    : Http3Request.Get(host, path);
ulong requestStream = http3.SendRequest(request);
Console.WriteLine($"→ {request.Method} gesendet (Stream {requestStream})"
                  + (postBody is not null ? $" — Rumpf {request.Body.Length} Bytes als DATA-Frame" : "")
                  + (qpackCapacity > 0 ? " (QPACK dynamische Tabelle aktiv)" : "") + "\n");

// Optional: Request-Cancellation (RFC 9114 §4.1.1) – den laufenden Download mitten im Transfer
// abbrechen (RESET_STREAM + STOP_SENDING mit H3_REQUEST_CANCELLED) und beweisen, dass die
// VERBINDUNG weiterlebt: ein zweites GET über dieselbe Verbindung liefert die volle Antwort.
if (args.Contains("--cancel"))
{
    for (int round = 0; round < 2; round++)
        Exchange(); // einen Teil der Antwort eintreffen lassen (Slow Start ⇒ längst nicht alles)
    http3.CancelRequest(requestStream);
    Console.WriteLine("→ Request mitten im Download abgebrochen (RESET_STREAM + STOP_SENDING, H3_REQUEST_CANCELLED) …");
    for (int round = 0; round < 6; round++)
        Exchange();
    if (http3.IsRequestCancelled(requestStream))
        Console.WriteLine("  Abbruch wirksam"
                          + (http3.RequestResetErrorCode(requestStream) is { } rc
                             ? $" — Server hat seine Antwortseite zurückgesetzt (Code 0x{rc:x})."
                             : " — Server hat den Sendefluss gestoppt."));
    else
        Console.WriteLine("  Antwort war bereits vollständig — Abbruch gemäß RFC 9114 §4.1.1 ignoriert (Antwort bleibt nutzbar).");

    ulong secondStream = http3.SendRequest(request);
    Http3Response? secondResponse = null;
    for (int round = 0; round < 120 && secondResponse is null; round++)
    {
        Exchange();
        http3.TryGetResponse(secondStream, out secondResponse);
    }
    if (secondResponse is null) { Console.WriteLine("✗ Zweites GET nach dem Abbruch fehlgeschlagen."); return 1; }
    Console.WriteLine($"HTTP/3 {secondResponse.Status} ({secondResponse.Body.Length} Bytes) über DIESELBE Verbindung nach dem Abbruch.");
    Console.WriteLine("✓✓ Request-Cancellation erfolgreich — die Verbindung lebt weiter (zweites GET ok).");
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

Console.WriteLine("== Antwort ==");
if (response is null) { Console.WriteLine("Keine vollständige Antwort erhalten."); return 1; }

// Interim-Responses (1xx, RFC 9114 §4.1) und Trailer-Sektion sichtbar machen, falls vorhanden.
foreach (var interim in response.InterimResponses)
    Console.WriteLine($"HTTP/3 {interim.Status} (Interim) — {string.Join(", ", interim.Headers.Select(h => $"{h.Name}: {h.Value}"))}");
Console.WriteLine($"HTTP/3 {response.Status}  ({response.GetHeader("content-type")})");
if (response.Trailers.Count > 0)
    Console.WriteLine($"Trailer: {string.Join(", ", response.Trailers.Select(h => $"{h.Name}: {h.Value}"))}");
if (postBody is not null)
    Console.WriteLine($"Rumpf ({response.Body.Length} Bytes): {(response.BodyText.Length <= 200 ? response.BodyText : response.BodyText[..200] + "…")}");
else
    Console.WriteLine($"Rumpf: {response.Body.Length} Bytes, Titel: {ExtractTitle(response.BodyText)}");
Console.WriteLine($"\n✓✓ HTTP/3-{request.Method} erfolgreich — Status {response.Status}"
                  + (lossPercent > 0 ? $", {dropped} Datagramme verworfen und via Retransmission überbrückt." : "."));
if (qpackCapacity > 0)
    Console.WriteLine($"  QPACK dynamische Tabelle: {http3.QpackEncoderInsertCount} Request-Inserts, "
                      + $"{http3.QpackDecoderInsertCount} Antwort-Inserts empfangen.");

// Optional: Session Resumption (RFC 8446 §2.2) bzw. 0-RTT Early Data (--zerortt). Zuerst das
// NewSessionTicket der ersten Verbindung einsammeln, dann eine frische Verbindung mit dem Ticket aufbauen;
// bei --zerortt geht die HTTP/3-Anfrage als Early Data raus, noch bevor der Handshake steht.
bool zeroRtt = args.Contains("--zerortt");
if (args.Contains("--resume") || zeroRtt)
{
    Console.WriteLine(zeroRtt ? "\n== 0-RTT (Early Data) ==" : "\n== Session Resumption ==");
    http3.KeepAliveInterval = TimeSpan.FromMilliseconds(200);
    var ticketWait = Stopwatch.StartNew();
    while (ticketWait.Elapsed.TotalSeconds < 4 && http3.NewSessionTickets.Count == 0)
        Exchange();

    Console.WriteLine($"  (Diagnose: {http3.Quic.NewSessionTicketMessagesSeen} NST-Nachricht(en) empfangen, "
                      + $"{http3.NewSessionTickets.Count} als Ticket verwertbar.)");
    if (http3.NewSessionTickets.Count == 0)
    {
        Console.WriteLine("✗ Kein NewSessionTicket erhalten — Resumption nicht möglich.");
        http3.Close();
        foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
        return 1;
    }

    ResumptionTicket ticket = http3.NewSessionTickets[0];
    Console.WriteLine($"→ {http3.NewSessionTickets.Count} Ticket(s) erhalten (Identity {ticket.Identity.Length} B). Neue Verbindung mit PSK …");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);

    using var socket2 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1500 };
    using var resumed = new Http3ClientConnection(host, new TransportParameters(), validation, qpackCapacity, cipherSuites, keyExchangeGroups, ticket);
    resumed.Start();

    ulong resumeStream;
    if (zeroRtt)
    {
        // 0-RTT: die Anfrage VOR dem Handshake queuen ⇒ sie geht als Early Data (Long Header 0x01) raus,
        // ohne auf ServerHello/Finished zu warten (0 Round-Trips bis zum Request).
        resumed.InitializeHttp3();
        resumeStream = resumed.SendRequest(Http3Request.Get(host, path));
        Console.WriteLine("→ HTTP/3-GET als 0-RTT Early Data gesendet (vor Handshake-Abschluss).");
    }
    else
    {
        for (int round = 0; round < 12 && !resumed.HandshakeConfirmed; round++)
            ExchangeWith(resumed, socket2);
        if (!resumed.HandshakeConfirmed) { Console.WriteLine("✗ Resumption-Handshake fehlgeschlagen."); return 1; }
        Console.WriteLine(resumed.ResumptionAccepted
            ? "✓ Handshake per Resumption abgeschlossen — PSK akzeptiert, KEIN Zertifikat gesendet."
            : "○ Server hat die Resumption abgelehnt — regulärer Handshake mit Zertifikat.");
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
    if (resumeResponse is null) { Console.WriteLine("✗ GET über die resümierte Verbindung fehlgeschlagen."); return 1; }

    if (zeroRtt)
        Console.WriteLine(resumed.EarlyDataAccepted
            ? "✓ 0-RTT AKZEPTIERT — die Anfrage lief als Early Data (kein Round-Trip bis zum Request)."
            : "○ Server hat 0-RTT abgelehnt — die Anfrage wurde regulär über 1-RTT beantwortet.");
    else
        Console.WriteLine(resumed.ResumptionAccepted
            ? "  (per Resumption, kein Zertifikat)" : "  (regulärer Handshake)");
    Console.WriteLine($"HTTP/3 {resumeResponse.Status} ({resumeResponse.Body.Length} Bytes) über die {(resumed.ResumptionAccepted ? "resümierte" : "neue")} Verbindung.");
    Console.WriteLine($"✓✓ Zweites GET nach {(zeroRtt ? "0-RTT Early Data" : "Session Resumption")} erfolgreich — Status {resumeResponse.Status}.");

    resumed.Close();
    foreach (byte[] dg in resumed.GetDatagramsToSend()) socket2.SendTo(dg, remote);
    return 0;
}

// Optional: WebTransport (draft-webtrans-http3, nur gegen den eigenen Server): Session über Extended
// CONNECT (:protocol=webtransport), dann Datagramm + uni-Stream + bidi-Stream (mit Echo) + Session-Ende.
if (args.Contains("--webtransport"))
{
    Console.WriteLine("\n== WebTransport über HTTP/3 (draft-ietf-webtrans-http3) ==");
    for (int round = 0; round < 20 && !http3.ServerSupportsWebTransport; round++)
        Exchange();
    if (!http3.ServerSupportsWebTransport) { Console.WriteLine("✗ Server unterstützt kein WebTransport."); return 1; }
    Console.WriteLine("→ Server-Support erkannt (WT_MAX_SESSIONS > 0, Extended CONNECT, Datagramme).");

    // Protokoll-Aushandlung (draft §3.3): Angebote in Präferenzreihenfolge; der Server wählt eines.
    ulong wtStream = http3.ConnectWebTransport(host, "/wt",
        availableProtocols: ["echo-v3", "echo-v2", "echo-v1"]);
    org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport.WebTransportSession? wt = null;
    for (int round = 0; round < 40 && wt is null; round++) { Exchange(); http3.TryGetWebTransportSession(wtStream, out wt); }
    if (wt is null) { Console.WriteLine($"✗ Session fehlgeschlagen (Status {http3.WebTransportConnectStatus(wtStream)})."); return 1; }
    Console.WriteLine($"→ Session {wt.SessionId} etabliert (Flow Control: {(wt.FlowControlEnabled ? "an" : "aus")}, " +
                      $"WT-Protocol: {wt.NegotiatedProtocol ?? "keines"}).");

    // Keying-Material-Exporter (draft §4.7 / RFC 8446 §7.5): muss byte-genau mit dem Server übereinstimmen.
    byte[] ekm = wt.ExportKeyingMaterial("demo-export", [1, 2, 3], 16);
    Console.WriteLine($"→ Keying-Material-Export (Label \"demo-export\"): {Convert.ToHexString(ekm).ToLowerInvariant()}");

    // Datagramm.
    wt.SendDatagram(System.Text.Encoding.UTF8.GetBytes("WT-Datagramm!"));
    byte[]? dg = null;
    for (int round = 0; round < 40 && dg is null; round++) { Exchange(); wt.TryReceiveDatagram(out dg); }
    Console.WriteLine(dg is not null ? $"← Datagramm-Echo: „{System.Text.Encoding.UTF8.GetString(dg)}\"" : "○ (kein Datagramm-Echo — unzuverlässig)");

    // Unidirektionaler Stream (Client → Server).
    var uni = wt.OpenUnidirectionalStream();
    uni!.Write(System.Text.Encoding.UTF8.GetBytes("uni-gruß")); uni.Finish();
    Console.WriteLine("→ Unidirektionaler WebTransport-Stream gesendet (0x54 ‖ Session-ID ‖ Daten).");

    // Bidirektionaler Stream mit Echo (Client → Server → Client).
    var bidi = wt.OpenBidirectionalStream();
    bidi!.Write(System.Text.Encoding.UTF8.GetBytes("bidi-ping")); bidi.Finish();
    var reply = new List<byte>();
    for (int round = 0; round < 60 && !bidi.IsReceiveComplete; round++) { Exchange(); reply.AddRange(bidi.Read()); }
    reply.AddRange(bidi.Read());
    Console.WriteLine($"← Bidi-Echo: „{System.Text.Encoding.UTF8.GetString(reply.ToArray())}\" (WT_STREAM 0x41)");

    wt.Close(0, "fertig");
    for (int round = 0; round < 10; round++) Exchange();
    Console.WriteLine($"✓✓ WebTransport erfolgreich — Session geschlossen (IsClosed={wt.IsClosed}).");
    http3.Close();
    foreach (byte[] d in http3.GetDatagramsToSend()) socket.SendTo(d, remote);
    return 0;
}

// Optional: HTTP-Datagramme (RFC 9297) über QUIC-DATAGRAM-Frames (RFC 9221, nur gegen den eigenen
// Server): unzuverlässige Nachrichten neben dem Byte-Strom eines Extended-CONNECT-Tunnels —
// die Grundlage von MASQUE/connect-udp und WebTransport.
if (args.Contains("--datagrams"))
{
    Console.WriteLine("\n== HTTP-Datagramme (RFC 9297/9221) ==");
    for (int round = 0; round < 20 && !http3.DatagramsNegotiated; round++)
        Exchange();
    if (!http3.DatagramsNegotiated) { Console.WriteLine("✗ Datagramme nicht ausgehandelt."); return 1; }
    Console.WriteLine($"→ Ausgehandelt: SETTINGS_H3_DATAGRAM = 1 beidseitig, max_datagram_frame_size = {http3.Quic.PeerMaxDatagramFrameSize}.");

    ulong dgStream = http3.SendExtendedConnect(host, "/", "datagram-echo");
    Http3Tunnel? dgTunnel = null;
    int dgStatus = 0;
    for (int round = 0; round < 40 && dgTunnel is null && dgStatus == 0; round++)
    {
        Exchange();
        http3.TryGetConnectResponse(dgStream, out dgStatus, out _, out dgTunnel);
    }
    if (dgTunnel is null) { Console.WriteLine($"✗ CONNECT fehlgeschlagen (Status {dgStatus})."); return 1; }
    Console.WriteLine($"→ CONNECT :protocol=datagram-echo angenommen (Status {dgStatus}).");

    int echoed = 0;
    for (int i = 1; i <= 3; i++)
    {
        byte[] ping = System.Text.Encoding.UTF8.GetBytes($"Datagramm #{i} über QUIC!");
        if (!dgTunnel.TrySendDatagram(ping)) { Console.WriteLine("✗ Senden verweigert."); return 1; }
        byte[]? pong = null;
        for (int round = 0; round < 40 && pong is null; round++)
        {
            Exchange();
            dgTunnel.TryReceiveDatagram(out pong);
        }
        if (pong is null) { Console.WriteLine($"✗ Kein Echo für Datagramm #{i} (unzuverlässig — hier lokal unerwartet)."); return 1; }
        Console.WriteLine($"← Echo #{i}: „{System.Text.Encoding.UTF8.GetString(pong)}\" ({pong.Length} Bytes, in einem DATAGRAM-Frame)");
        echoed++;
    }
    Console.WriteLine($"✓✓ {echoed}/3 HTTP-Datagramme geecht — RFC 9297 (Quarter Stream ID) über RFC 9221 (DATAGRAM-Frames).");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return 0;
}

// Optional: WebSocket über HTTP/3 (RFC 9220, nur gegen den eigenen Server): Extended CONNECT mit
// :protocol=websocket (RFC 8441), dann RFC-6455-Frames durch den Tunnel (DATA-Frames, RFC 9114 §4.4).
if (args.Contains("--websocket"))
{
    Console.WriteLine("\n== WebSocket über HTTP/3 (RFC 9220) ==");
    for (int round = 0; round < 20 && !http3.ServerEnablesConnectProtocol; round++)
        Exchange();
    if (!http3.ServerEnablesConnectProtocol) { Console.WriteLine("✗ Server erlaubt kein Extended CONNECT."); return 1; }
    Console.WriteLine("→ SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 empfangen — Extended CONNECT erlaubt.");

    ulong wsStream = http3.SendExtendedConnect(host, "/chat", "websocket",
        [new org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack.HeaderField("sec-websocket-version", "13")]);
    int wsStatus = 0;
    Http3Tunnel? tunnel = null;
    for (int round = 0; round < 40 && tunnel is null && wsStatus == 0; round++)
    {
        Exchange();
        http3.TryGetConnectResponse(wsStream, out wsStatus, out _, out tunnel);
    }
    if (tunnel is null) { Console.WriteLine($"✗ CONNECT fehlgeschlagen (Status {wsStatus})."); return 1; }
    Console.WriteLine($"→ CONNECT :protocol=websocket angenommen (Status {wsStatus}) — Stream {wsStream} ist jetzt der Tunnel.");

    var ws = new WebSocketConnection(tunnel, WebSocketRole.Client);
    _ = ws.SendTextAsync("Hallo WebSocket über HTTP/3 — from scratch!", CancellationToken.None);
    var receive = ws.ReceiveAsync(CancellationToken.None);
    for (int round = 0; round < 100 && !receive.IsCompleted; round++)
        Exchange();
    if (!receive.IsCompleted || receive.Result is not { } wsEcho) { Console.WriteLine("✗ Kein WebSocket-Echo erhalten."); return 1; }
    Console.WriteLine($"← Echo: „{System.Text.Encoding.UTF8.GetString(wsEcho.Payload)}\"");

    _ = ws.CloseAsync(1000, "fertig", CancellationToken.None);
    var closing = ws.ReceiveAsync(CancellationToken.None);
    for (int round = 0; round < 40 && !closing.IsCompleted; round++)
        Exchange();
    Console.WriteLine(closing.IsCompleted && closing.Result is null
        ? "✓ Close-Handshake vollzogen (RFC 6455 §5.5.1) — Tunnel geordnet beendet."
        : "✗ Close-Handshake nicht vollzogen.");
    Console.WriteLine("✓✓ WebSocket über HTTP/3 erfolgreich — RFC 9220 + RFC 8441 + RFC 6455 über unserem Stack.");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return 0;
}

// Optional: Priorisierung (RFC 9218) vorführen — nur gegen den eigenen Server sinnvoll (Route /big):
// zwei konkurrierende Downloads, der ZWEITE mit `priority: u=0` (dringlich) — der Server bedient ihn
// zuerst, obwohl er später angefragt wurde. Danach dasselbe mit PRIORITY_UPDATE-Reprioritisierung.
if (args.Contains("--priorities"))
{
    Console.WriteLine("\n== Priorisierung (RFC 9218) ==");
    ulong slow = http3.SendRequest(Http3Request.Get(host, "/big"));                                       // u=3 (Default)
    ulong fast = http3.SendRequest(Http3Request.Get(host, "/big") with { Priority = new Http3Priority(0, false) }); // u=0
    Console.WriteLine($"→ Zwei GET /big: Stream {slow} (Default u=3), danach Stream {fast} (priority: u=0)");

    ulong? firstDone = null;
    Http3Response? slowResp = null, fastResp = null;
    for (int round = 0; round < 400 && (slowResp is null || fastResp is null); round++)
    {
        Exchange();
        if (slowResp is null && http3.TryGetResponse(slow, out slowResp) && firstDone is null) firstDone = slow;
        if (fastResp is null && http3.TryGetResponse(fast, out fastResp) && firstDone is null) firstDone = fast;
    }
    if (slowResp is null || fastResp is null) { Console.WriteLine("✗ Antworten unvollständig."); return 1; }
    Console.WriteLine(firstDone == fast
        ? $"✓ Der dringlichere Download (u=0, Stream {fast}) kam ZUERST an — obwohl später angefragt."
        : "✗ Erwartet war, dass der u=0-Download zuerst fertig wird!");

    // Reprioritisierung (RFC 9218 §6/§7): „Prefetch" mit u=0 starten, dann per PRIORITY_UPDATE auf
    // u=7 (Hintergrund) zurückstufen — der Default-Download überholt ihn.
    ulong prefetch = http3.SendRequest(Http3Request.Get(host, "/big") with { Priority = new Http3Priority(0, false) });
    ulong normal = http3.SendRequest(Http3Request.Get(host, "/big"));
    http3.SendPriorityUpdate(prefetch, new Http3Priority(7, false));
    Console.WriteLine($"→ Reprioritisierung: Stream {prefetch} (Header u=0) per PRIORITY_UPDATE auf u=7 zurückgestuft; Stream {normal} (u=3)");

    firstDone = null;
    Http3Response? prefetchResp = null, normalResp = null;
    for (int round = 0; round < 400 && (prefetchResp is null || normalResp is null); round++)
    {
        Exchange();
        if (prefetchResp is null && http3.TryGetResponse(prefetch, out prefetchResp) && firstDone is null) firstDone = prefetch;
        if (normalResp is null && http3.TryGetResponse(normal, out normalResp) && firstDone is null) firstDone = normal;
    }
    if (prefetchResp is null || normalResp is null) { Console.WriteLine("✗ Antworten unvollständig."); return 1; }
    Console.WriteLine(firstDone == normal
        ? $"✓ Das PRIORITY_UPDATE (u=7) überschrieb den Header (u=0) — Stream {normal} überholte den degradierten Prefetch."
        : "✗ Erwartet war, dass das PRIORITY_UPDATE den Prefetch zurückstuft!");
    Console.WriteLine($"✓✓ RFC-9218-Priorisierung erfolgreich ({slowResp.Body.Length} Bytes je Download, 4 Downloads).");
    http3.Close();
    foreach (byte[] dg in http3.GetDatagramsToSend()) socket.SendTo(dg, remote);
    return firstDone == normal ? 0 : 1;
}

// Optional: GOAWAY / Graceful Shutdown beobachten (RFC 9114 §5.2, nur gegen `H3Server --goaway`):
// der Server kündigt nach der Antwort per GOAWAY den Abbau an; neue Requests sind dann verboten,
// und die Verbindung endet anständig mit H3_NO_ERROR (CONNECTION_CLOSE Typ 0x1d).
if (args.Contains("--goaway"))
{
    Console.WriteLine("\n== GOAWAY / Graceful Shutdown ==");
    for (int round = 0; round < 40 && http3.GoAwayStreamId is null && http3.PeerCloseFrame is null; round++)
        Exchange();

    if (http3.GoAwayStreamId is not { } goAwayId)
    {
        Console.WriteLine("✗ Kein GOAWAY erhalten.");
        return 1;
    }
    Console.WriteLine($"→ GOAWAY empfangen: Grenze Stream-ID {goAwayId} — keine neuen Requests auf dieser Verbindung.");
    try
    {
        http3.SendRequest(Http3Request.Get(host, path));
        Console.WriteLine("✗ Der neue Request hätte verweigert werden müssen!");
        return 1;
    }
    catch (InvalidOperationException)
    {
        Console.WriteLine("✓ Neuer Request korrekt verweigert (RFC 9114 §5.2 MUST NOT).");
    }

    for (int round = 0; round < 40 && http3.PeerCloseFrame is null; round++)
        Exchange();
    if (http3.PeerCloseFrame is not { } close)
    {
        Console.WriteLine("✗ Kein CONNECTION_CLOSE des Servers erhalten.");
        return 1;
    }
    Console.WriteLine($"✓✓ Server schloss anständig: CONNECTION_CLOSE ({(close.IsApplicationError ? "Application" : "Transport")}) "
                      + $"Code 0x{close.ErrorCode:x}{(close.ErrorCode == Http3Error.NoError ? " = H3_NO_ERROR" : "")}.");
    return 0;
}

// Optional: 1-RTT-Key-Update (RFC 9001 §6) und ein zweites GET unter den rotierten Schlüsseln.
if (keyUpdate)
{
    http3.Quic.InitiateKeyUpdate();
    Console.WriteLine($"\n== Key Update == (Key-Phase {(http3.Quic.CurrentKeyPhase ? 1 : 0)})");
    ulong stream2 = http3.SendRequest(Http3Request.Get(host, path));
    Http3Response? response2 = null;
    for (int round = 0; round < 120; round++)
    {
        Exchange();
        if (http3.TryGetResponse(stream2, out response2) && response2 is not null)
            break;
    }
    if (response2 is null) { Console.WriteLine("Zweites GET nach Key Update fehlgeschlagen."); return 1; }
    Console.WriteLine($"HTTP/3 {response2.Status} ({response2.Body.Length} Bytes) unter neuen Schlüsseln"
                      + $" — Key-Phase {(http3.Quic.CurrentKeyPhase ? 1 : 0)}, {http3.Quic.KeyUpdateCount} Rotationen.");
    Console.WriteLine("✓✓ Zweites GET nach Key Update erfolgreich.");
}

// Optional: Connection-ID-Rotation (RFC 9000 §5.1) – DCID auf eine vom Server ausgegebene CID umstellen.
if (rotateCid)
{
    for (int round = 0; round < 6; round++) // dem Server Zeit geben, NEW_CONNECTION_ID zu senden
        Exchange();
    Console.WriteLine($"\n== Connection-ID-Rotation == (bekannte Server-CIDs: {http3.Quic.RemoteConnectionIdCount})");
    if (http3.Quic.RotateDestinationConnectionId())
    {
        Console.WriteLine($"→ DCID gewechselt auf {http3.Quic.DestinationConnectionId}; zweites GET unter neuer CID …");
        ulong stream3 = http3.SendRequest(Http3Request.Get(host, path));
        Http3Response? response3 = null;
        for (int round = 0; round < 120; round++)
        {
            Exchange();
            if (http3.TryGetResponse(stream3, out response3) && response3 is not null)
                break;
        }
        if (response3 is null) { Console.WriteLine("Zweites GET nach CID-Rotation fehlgeschlagen."); return 1; }
        Console.WriteLine($"HTTP/3 {response3.Status} ({response3.Body.Length} Bytes) unter neuer Connection ID.");
        Console.WriteLine("✓✓ Zweites GET nach Connection-ID-Rotation erfolgreich.");
    }
    else
        Console.WriteLine("Server hat keine zusätzliche Connection ID angeboten — keine Rotation möglich.");
}

// Optional: Connection Migration (RFC 9000 §9) – den lokalen UDP-Port wechseln und über den neuen Pfad
// ein weiteres GET holen. Der Server demultiplext über die Connection ID und validiert den neuen Pfad.
if (migrate)
{
    using var migratedSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 1500 };
    migratedSocket.Bind(new IPEndPoint(IPAddress.Any, 0));
    Console.WriteLine($"\n== Connection Migration == neuer lokaler Port {((IPEndPoint)migratedSocket.LocalEndPoint!).Port}; zweites GET über den neuen Pfad …");

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
                EndPoint f = new IPEndPoint(IPAddress.Any, 0);
                int m = migratedSocket.ReceiveFrom(buf, ref f);
                http3.ProcessDatagram(buf.AsSpan(0, m));
            }
            catch (SocketException) { break; }
        }
        http3.TryGetResponse(migStream, out migResponse);
    }

    if (migResponse is null) { Console.WriteLine("Zweites GET nach Migration fehlgeschlagen."); return 1; }
    Console.WriteLine($"HTTP/3 {migResponse.Status} ({migResponse.Body.Length} Bytes) über den neuen Pfad.");
    Console.WriteLine("✓✓ Zweites GET nach Connection Migration erfolgreich (Verbindung überlebt den Adresswechsel).");
}

// Optional: die Verbindung per Keep-Alive-PING (RFC 9000 §10.1.2) N Sekunden untätig offen halten.
int holdSeconds = ParseIntArg(args, "--hold=", 0);
if (holdSeconds > 0)
{
    http3.KeepAliveInterval = TimeSpan.FromMilliseconds(500);
    Console.WriteLine($"\n== Keep-Alive == halte die Verbindung {holdSeconds}s untätig offen (PING alle 500 ms) …");
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed.TotalSeconds < holdSeconds && !http3.IsIdleTimedOut)
        Exchange();
    Console.WriteLine(http3.IsIdleTimedOut
        ? "✗ Verbindung wurde trotz Keep-Alive geschlossen."
        : $"✓ Verbindung nach {holdSeconds}s untätig noch offen — Idle-Timeout via Keep-Alive verhindert.");
}

// Anständiger Abbau (RFC 9000 §10.2): CONNECTION_CLOSE mit NO_ERROR senden.
http3.Close();
foreach (byte[] datagram in http3.GetDatagramsToSend())
    socket.SendTo(datagram, remote);
Console.WriteLine("→ Verbindung geschlossen (CONNECTION_CLOSE, NO_ERROR).");
return 0;

void Exchange() => ExchangeWith(http3, socket);

void ExchangeWith(Http3ClientConnection conn, Socket sock)
{
    conn.CheckTimeouts(); // Loss-Detection/PTO
    foreach (byte[] datagram in conn.GetDatagramsToSend())
    {
        if (Drop()) continue; // ausgehender Verlust
        sock.SendTo(datagram, remote);
    }

    byte[] buffer = new byte[2048];
    for (int i = 0; i < 32; i++)
    {
        try
        {
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            int n = sock.ReceiveFrom(buffer, ref from);
            if (Drop()) continue; // eingehender Verlust
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

static int ParseIntArg(string[] args, string prefix, int fallback)
{
    string? arg = args.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.Ordinal));
    return arg is not null && int.TryParse(arg[prefix.Length..], out int v) ? v : fallback;
}

static string ExtractTitle(string html)
{
    int a = html.IndexOf("<title>", StringComparison.OrdinalIgnoreCase);
    int b = html.IndexOf("</title>", StringComparison.OrdinalIgnoreCase);
    return a >= 0 && b > a ? html[(a + 7)..b].Trim() : "(kein Titel)";
}
