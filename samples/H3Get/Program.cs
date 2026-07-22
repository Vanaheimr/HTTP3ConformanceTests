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
// H3Get: Ein echtes HTTP/3-GET, from scratch. Optional mit künstlichem Paketverlust (--loss=N),
// um Loss Recovery (RFC 9002) nachzuweisen: der Handshake + Download überstehen verworfene Pakete
// dank Retransmission (Paket-/Zeitschwelle + PTO). Das Serverzertifikat wird standardmäßig geprüft
// (Kette gegen die System-Roots + Hostname); -k/--insecure überspringt das wie curl (nur für
// selbstsignierte Testserver, z. B. den lokalen H3Server).
// ---------------------------------------------------------------------------------------------

string host = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "cloudflare-quic.com";
string path = args.Where(a => !a.StartsWith('-')).Skip(1).FirstOrDefault() ?? "/";
int port = ParseIntArg(args, "--port=", 443);
int lossPercent = ParseLoss(args);
bool insecure = args.Contains("-k") || args.Contains("--insecure");
bool keyUpdate = args.Contains("--key-update");
bool rotateCid = args.Contains("--rotate-cid");
bool migrate = args.Contains("--migrate");
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
using var http3 = new Http3ClientConnection(host, transportParams, validation, qpackCapacity, cipherSuites, keyExchangeGroups);
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
Console.WriteLine($"  Serverzertifikat: {http3.Quic.ServerCertificate?.Subject} — "
                  + (insecure ? "Signatur geprüft, Kette/Hostname übersprungen (-k)"
                             : "Signatur + Kette + Hostname geprüft") + "\n");

http3.InitializeHttp3();
// Kurz Datagramme pendeln lassen, damit die SETTINGS des Servers ankommen (Kapazität lernen).
for (int round = 0; round < 3; round++)
    Exchange();
ulong requestStream = http3.SendRequest(Http3Request.Get(host, path));
Console.WriteLine($"→ GET gesendet (Stream {requestStream})"
                  + (qpackCapacity > 0 ? " (QPACK dynamische Tabelle aktiv)" : "") + "\n");

Http3Response? response = null;
for (int round = 0; round < 120; round++)
{
    Exchange();
    if (http3.TryGetResponse(requestStream, out response) && response is not null)
        break;
}

Console.WriteLine("== Antwort ==");
if (response is null) { Console.WriteLine("Keine vollständige Antwort erhalten."); return 1; }

Console.WriteLine($"HTTP/3 {response.Status}  ({response.GetHeader("content-type")})");
Console.WriteLine($"Rumpf: {response.Body.Length} Bytes, Titel: {ExtractTitle(response.BodyText)}");
Console.WriteLine($"\n✓✓ HTTP/3-GET erfolgreich — Status {response.Status}"
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
