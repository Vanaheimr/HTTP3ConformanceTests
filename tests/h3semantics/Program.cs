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
using System.Security.Cryptography;
using System.Text;

#endregion

// h3semantics: HTTP/3 request/response semantics of the demo server (samples/H3Server), checked
// from the OTHER side of the wire by a client nobody here wrote — .NET's HttpClient, which speaks
// HTTP/3 through msquic (Microsoft's QUIC stack).
//
// That is the whole design. Hermod's own HermodTests/HTTP3 suite already drives our client against
// our server in-process, and it does so far more thoroughly than this file ever will. What it
// cannot do is disagree with us: both ends share the same reading of the RFCs, the same framing
// code and the same bugs. msquic shares none of that, so every check below is a check that two
// independent implementations read RFC 9114 the same way.
//
// Needs the demo host running:  dotnet run --project samples/H3Server -- 4433
// Or just let tests/run-tests.sh start it.

string host = Environment.GetEnvironmentVariable("H3_HOST") ?? "localhost";
int    port = int.TryParse(Environment.GetEnvironmentVariable("H3_PORT"), out int p) ? p : 4433;
string root = $"https://{host}:{port}";

if (!System.Net.Quic.QuicConnection.IsSupported)
{
    // Not a failure of ours: no msquic, no foreign client, no verdict to report. Say so plainly
    // rather than reporting 0/0 checks passed, which would read like a green run.
    Console.WriteLine("h3semantics: SKIPPED — System.Net.Quic reports no QUIC support on this machine.");
    Console.WriteLine("  (Windows: ships with the runtime. Linux: needs libmsquic.)");
    return 2;
}

// The demo server is self-signed by design, so the trust decision is ours to make — this is the
// harness equivalent of curl -k. The signature over the handshake transcript is still verified by
// msquic; what we waive is only the chain, exactly like every other client we test with.
var handler = new SocketsHttpHandler {
    SslOptions = new System.Net.Security.SslClientAuthenticationOptions {
        RemoteCertificateValidationCallback = (_, _, _, _) => true
    }
};

using var client = new HttpClient(handler) {
    DefaultRequestVersion = HttpVersion.Version30,
    DefaultVersionPolicy  = HttpVersionPolicy.RequestVersionExact,
    Timeout               = TimeSpan.FromSeconds(20)
};

int passed = 0;
int failed = 0;

void Check(string name, bool ok, string detail = "")
{
    if (ok) { passed++; Console.WriteLine($"  ✓ {name}" + (detail.Length > 0 ? $"  ({detail})" : "")); }
    else    { failed++; Console.WriteLine($"  ✗ {name}" + (detail.Length > 0 ? $"  — {detail}" : "")); }
}

// A harness that throws tells you less than a harness that reports. A hang here is a finding about
// the server, so it has to arrive as a failed check with the remaining checks still run — not as a
// stack trace that hides everything after it.
async Task<(HttpResponseMessage? Response, byte[] Body, string? Error)> Try(HttpMethod method, string path,
                                                                           Action<HttpRequestMessage>? configure = null)
{
    try
    {
        var (response, body) = await Send(method, path, configure);
        return (response, body, null);
    }
    catch (Exception e)
    {
        return (null, [], e.InnerException?.Message ?? e.Message);
    }
}

async Task<(HttpResponseMessage Response, byte[] Body)> Send(HttpMethod method, string path,
                                                             Action<HttpRequestMessage>? configure = null)
{
    // Version + policy belong on the request, not only on the HttpClient: SendAsync does not apply
    // the client's defaults, and a request that falls back to HTTP/1.1 would offer the wrong ALPN
    // and be dropped by a server that only speaks h3.
    var request = new HttpRequestMessage(method, root + path) {
        Version       = HttpVersion.Version30,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact
    };
    configure?.Invoke(request);
    HttpResponseMessage response = await client.SendAsync(request);
    return (response, await response.Content.ReadAsByteArrayAsync());
}

Console.WriteLine($"=== h3semantics — {root} (client: .NET HttpClient over msquic) ===\n");

Console.WriteLine("=== GET / ===");
var (index, indexBody) = await Send(HttpMethod.Get, "/");
Check("200 OK",                index.StatusCode == HttpStatusCode.OK, $"{(int) index.StatusCode}");
Check("negotiated HTTP/3",     index.Version == HttpVersion.Version30, $"HTTP/{index.Version}");
Check("content-type text/html", index.Content.Headers.ContentType?.MediaType == "text/html",
      index.Content.Headers.ContentType?.ToString() ?? "(none)");
Check("server header",         index.Headers.TryGetValues("server", out var srv) && srv.Contains("http3-from-scratch"));
Check("body is the demo page", Encoding.UTF8.GetString(indexBody).Contains("hand-built HTTP/3 server"),
      $"{indexBody.Length} bytes");

Console.WriteLine("\n=== GET /big — a 300 000 byte body across many packets ===");
var (big, bigBody) = await Send(HttpMethod.Get, "/big");
Check("200 OK",                big.StatusCode == HttpStatusCode.OK, $"{(int) big.StatusCode}");
Check("exactly 300 000 bytes", bigBody.Length == 300_000, $"{bigBody.Length} bytes");
// The server fills this with (i * 13 + 5) mod 256. Checking the pattern rather than the length is
// what makes this a reassembly test: a stream that loses, reorders or duplicates a range still has
// the right size surprisingly often.
int firstBadByte = -1;
for (int i = 0; i < bigBody.Length; i++)
    if (bigBody[i] != (byte) (i * 13 + 5)) { firstBadByte = i; break; }
Check("body byte-exact",       firstBadByte < 0,
      firstBadByte < 0 ? "pattern (i*13+5) holds over all 300 000" : $"first mismatch at offset {firstBadByte}");
Check("content-type octet-stream", big.Content.Headers.ContentType?.MediaType == "application/octet-stream",
      big.Content.Headers.ContentType?.ToString() ?? "(none)");

Console.WriteLine("\n=== POST /echo — request bodies as DATA frames (RFC 9114 §4.1) ===");
// The sizes straddle the interesting boundaries: below one packet, above the MTU, and above the
// server's initial 256 KiB stream window, so it must extend credit mid-upload.
foreach (int size in (int[]) [16, 1_400, 65_536, 300_000])
{
    byte[] payload = new byte[size];
    RandomNumberGenerator.Fill(payload);
    var (echo, echoBody, error) = await Try(HttpMethod.Post, "/echo", r => {
        r.Content = new ByteArrayContent(payload);
        r.Content.Headers.TryAddWithoutValidation("Content-Type", "application/octet-stream");
    });
    Check($"echo {size,7} bytes -> 200",  echo?.StatusCode == HttpStatusCode.OK,
          error ?? $"{(int?) echo?.StatusCode}");
    Check($"echo {size,7} bytes byte-exact", echo is not null && echoBody.AsSpan().SequenceEqual(payload),
          error ?? $"sent {payload.Length}, got {echoBody.Length}");
}

Console.WriteLine("\n=== GET /hints — trailers after the content (RFC 9114 §4.1) ===");
var (hints, hintsBody) = await Send(HttpMethod.Get, "/hints");
Check("200 OK",                hints.StatusCode == HttpStatusCode.OK, $"{(int) hints.StatusCode}");
string expectedChecksum = Convert.ToHexString(SHA256.HashData(hintsBody))[..16].ToLowerInvariant();
bool hasTrailer = hints.TrailingHeaders.TryGetValues("checksum", out var checksums);
string? actualChecksum = checksums?.FirstOrDefault();
Check("trailer section present", hasTrailer, hasTrailer ? "checksum" : "no trailing headers");
Check("trailer checksum matches the body we received", actualChecksum == expectedChecksum,
      $"trailer={actualChecksum ?? "(none)"} computed={expectedChecksum}");

Console.WriteLine("\n=== MAX_FIELD_SECTION_SIZE — the server announces 16384 (RFC 9114 §4.2.2) ===");
// The limit counts name + value + 32 per field, so ~24 KB of value is comfortably over it.
//
// Two outcomes are conformant, and which one we get is itself the interesting part. §4.2.2 says a
// peer that received the setting SHOULD NOT send a larger header section — and msquic takes that
// seriously: it refuses locally, naming our number back at us, so no request is ever sent. That is
// a stronger result than a 431 would be, because it proves a foreign stack parsed our SETTINGS and
// acted on them. A client that does send it must get 431 without our handler ever running.
//
// What must not happen: a 200, or a hang.
var (tooBig, _, tooBigError) = await Try(HttpMethod.Get, "/", r =>
    r.Headers.TryAddWithoutValidation("x-oversized", new string('q', 24_000)));
bool refusedByPeer  = tooBig is null && tooBigError?.Contains("16384", StringComparison.Ordinal) == true;
bool rejectedByUs   = tooBig?.StatusCode == HttpStatusCode.RequestHeaderFieldsTooLarge;
Check("oversized header section refused",
      refusedByPeer || rejectedByUs,
      refusedByPeer ? "peer honoured our SETTINGS and never sent it"
                    : rejectedByUs ? "431 from us"
                    : tooBigError ?? $"{(int?) tooBig?.StatusCode}");

// And the connection must survive it: a field-section overflow is a stream error, not a connection
// error (§4.2.2). If the server tore the connection down, this next request cannot complete.
var (afterTooBig, _, afterError) = await Try(HttpMethod.Get, "/");
Check("connection survives it",
      afterTooBig?.StatusCode == HttpStatusCode.OK, afterError ?? $"{(int?) afterTooBig?.StatusCode}");

Console.WriteLine("\n=== Connection reuse — many requests, one QUIC connection ===");
// Nothing above proves the connection survived: HttpClient would happily open a fresh one per
// request and every check would still pass. Twenty small requests in a row would be twenty
// handshakes if it did not, and the server log makes that visible at a glance.
var reuse = new List<int>();
for (int i = 0; i < 20; i++)
{
    var (r, _) = await Send(HttpMethod.Get, $"/reuse-{i}");
    reuse.Add((int) r.StatusCode);
}
Check("20 sequential requests all 200", reuse.All(s => s == 200),
      $"{reuse.Count(s => s == 200)}/20");

Console.WriteLine("\n=== Long-lived connection — past initial_max_streams_bidi (RFC 9000 §4.6) ===");
// Every HTTP/3 request takes a fresh bidirectional stream, and a stream ID is never reused. The
// transport parameter only grants the FIRST 100; after that the peer must be given more credit with
// MAX_STREAMS as earlier streams finish, or the connection can never carry request 101.
//
// 120 requests is barely a long-lived connection — a browser tab reaches it on one page — so this
// is not an endurance test. It is the smallest number that crosses the boundary.
// A connection of its own, so the number this reports is the limit itself and not the limit minus
// whatever the checks above already spent.
int served = 0;
string? wall = null;
using (var freshHandler = new SocketsHttpHandler {
           SslOptions = new System.Net.Security.SslClientAuthenticationOptions {
               RemoteCertificateValidationCallback = (_, _, _, _) => true
           }
       })
using (var freshClient = new HttpClient(freshHandler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(15) })
{
    for (int i = 0; i < 120; i++)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, root + "/") {
                Version       = HttpVersion.Version30,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            HttpResponseMessage response = await freshClient.SendAsync(request);
            if (response.StatusCode != HttpStatusCode.OK) { wall = $"{(int) response.StatusCode}"; break; }
            served++;
        }
        catch (Exception e) { wall = (e.InnerException ?? e).Message; break; }
    }
}
Check("120 requests on one connection", served == 120,
      wall is null ? $"{served}/120" : $"stalled after {served} — {wall}");

Console.WriteLine("\n=== Large uploads on fresh connections — 16 x 300 000 bytes, each the first request ===");
// The 300 KB echo above rides a connection that is already warm. A fresh connection's first large
// upload is different: it bursts through slow start, loses datagrams even on loopback, and msquic
// retransmits the lost bytes in frames cut differently from the originals. A shorter frame at an
// offset the receiver already held used to replace the longer one there, dropping its tail - bytes
// that had been acknowledged and so were never sent again. The request then sat complete on the
// wire and unread on the server until the idle timeout (Hermod#129, fixed in Hermod#159).
//
// About one fresh connection in five hit it, so one trial proves little: sixteen catch a return of
// it in roughly 97 runs out of 100. A healthy upload takes ~50 ms; 5 s is a stall, not a slow run.
int freshOk = 0;
string? freshFailure = null;
for (int i = 0; i < 16; i++)
{
    using var uploadHandler = new SocketsHttpHandler {
        SslOptions = new System.Net.Security.SslClientAuthenticationOptions {
            RemoteCertificateValidationCallback = (_, _, _, _) => true
        }
    };
    using var uploadClient = new HttpClient(uploadHandler) { Timeout = TimeSpan.FromSeconds(5) };
    byte[] upload = new byte[300_000];
    RandomNumberGenerator.Fill(upload);
    try
    {
        var request = new HttpRequestMessage(HttpMethod.Post, root + "/echo") {
            Version       = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content       = new ByteArrayContent(upload)
        };
        HttpResponseMessage response = await uploadClient.SendAsync(request);
        byte[] echoed = await response.Content.ReadAsByteArrayAsync();
        if (response.StatusCode == HttpStatusCode.OK && echoed.AsSpan().SequenceEqual(upload))
            freshOk++;
        else
            freshFailure ??= $"connection {i}: {(int) response.StatusCode}, {echoed.Length} bytes back";
    }
    catch (TaskCanceledException)
    {
        freshFailure ??= $"connection {i}: no response within 5 s";
    }
    catch (Exception e)
    {
        freshFailure ??= $"connection {i}: {(e.InnerException ?? e).Message}";
    }
}
Check("16 fresh connections, each a 300 000-byte POST first, all echoed", freshOk == 16,
      freshFailure is null ? "16/16" : $"{freshOk}/16 — first failure on {freshFailure}");

Console.WriteLine("\n=== Concurrency — 16 requests in flight at once ===");
// Each becomes its own bidirectional QUIC stream. This is where a server that serialises requests,
// or reuses per-connection state across streams, falls over.
var inFlight = Enumerable.Range(0, 16).Select(async i => {
    var (r, body) = await Send(HttpMethod.Get, i % 2 == 0 ? "/" : "/hints");
    return r.StatusCode == HttpStatusCode.OK && body.Length > 0;
});
bool[] concurrent = await Task.WhenAll(inFlight);
Check("16 concurrent requests all 200 with a body", concurrent.All(ok => ok),
      $"{concurrent.Count(ok => ok)}/16");

Console.WriteLine("\n=== The server's own timers — the path goes dark mid-response (RFC 9002 §6.2) ===");
// Every check above has the client talking, and a server that acts only when a datagram arrives
// passes all of them. This one takes the client away. A UDP relay between msquic and the server
// forwards a GET /big until 40 datagrams of the response are through, then drops everything in
// both directions for 1.5 s. Nothing reaches the server in that time, so whatever it sends then, it
// sends on a timer of its own: the probe timeout (PTO) fires because acknowledgments stopped, and
// the server probes. On loopback the PTO is a few tens of milliseconds.
//
// The demo host used to look at its timers only after a full second without any datagram, from
// any client. Its first probe came after a second on a quiet server, and never while another
// connection kept it busy. The second case is the one that pins the fix: a server that merely waits
// less for silence still never hears silence while a neighbour talks.
//
// The first 50 ms after the cut do not count: the server may still be answering what reached it
// just before, and that needs no timer.
const int darkAfterDatagrams = 40;
var darkFor     = TimeSpan.FromMilliseconds(1500);
var darkGrace   = TimeSpan.FromMilliseconds(50);
var probeWithin = TimeSpan.FromMilliseconds(400);

HttpClient FreshClient(TimeSpan timeout) =>
    new(new SocketsHttpHandler {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions {
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        }) { Timeout = timeout };

async Task<byte[]> GetBody(HttpClient via, string url)
{
    var request = new HttpRequestMessage(HttpMethod.Get, url) {
        Version       = HttpVersion.Version30,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact
    };
    HttpResponseMessage response = await via.SendAsync(request);
    return await response.Content.ReadAsByteArrayAsync();
}

async Task<(TimeSpan? OwnSend, int SentWhileDark, string? Failure)> DarkPath(bool busyNeighbour)
{
    IPAddress serverAddress = (await Dns.GetHostAddressesAsync(host))
                              .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).First();
    using var relay = new DarkRelay(new IPEndPoint(serverAddress, port), darkAfterDatagrams, darkFor, darkGrace);
    using var viaRelay = FreshClient(TimeSpan.FromSeconds(15));
    Task<byte[]> response = GetBody(viaRelay, $"https://127.0.0.1:{relay.Port}/big");

    if (await Task.WhenAny(relay.WentDark, response, Task.Delay(10_000)) != relay.WentDark)
        return (null, 0, response.IsCompletedSuccessfully
                             ? $"the response was through before {darkAfterDatagrams} datagrams, nothing to cut"
                             : $"the path never went dark: {response.Exception?.InnerException?.Message ?? "no response"}");

    // The neighbour talks to the server directly, back to back, for as long as the path is dark.
    Task neighbour = Task.CompletedTask;
    if (busyNeighbour)
        neighbour = Task.Run(async () => {
            using var busy = FreshClient(TimeSpan.FromSeconds(10));
            var talking = Stopwatch.StartNew();
            while (talking.Elapsed < darkFor)
                try { await GetBody(busy, root + "/big"); } catch { return; }
        });
    await Task.Delay(darkFor);
    await neighbour;
    (TimeSpan? ownSend, int sentWhileDark) = (relay.FirstOwnSend, relay.SentWhileDark);

    try
    {
        byte[] body = await response;
        bool exact = body.Length == 300_000;
        for (int i = 0; exact && i < body.Length; i++)
            exact = body[i] == (byte) (i * 13 + 5);
        return (ownSend, sentWhileDark, exact ? null : $"{body.Length} bytes, not the 300 000-byte pattern");
    }
    catch (Exception e)
    {
        return (ownSend, sentWhileDark, $"no response once the path was back: {(e.InnerException ?? e).Message}");
    }
}

string OwnSendDetail((TimeSpan? OwnSend, int SentWhileDark, string? Failure) run) =>
    run.OwnSend is { } at
        ? $"first datagram of its own after {at.TotalMilliseconds:F0} ms, {run.SentWhileDark} while dark"
        : $"nothing of its own in {darkFor.TotalMilliseconds:F0} ms of darkness"
          + (run.Failure is null ? "" : $" — {run.Failure}");

var quietRun = await DarkPath(busyNeighbour: false);
Check($"a quiet server probes within {probeWithin.TotalMilliseconds:F0} ms",
      quietRun.OwnSend <= probeWithin, OwnSendDetail(quietRun));
var busyRun = await DarkPath(busyNeighbour: true);
Check($"a busy server probes within {probeWithin.TotalMilliseconds:F0} ms too",
      busyRun.OwnSend <= probeWithin, OwnSendDetail(busyRun));
Check("both responses complete byte-exact once the path is back",
      quietRun.Failure is null && busyRun.Failure is null,
      quietRun.Failure ?? busyRun.Failure ?? "2 x 300 000 bytes, pattern intact");

Console.WriteLine($"\n=== {passed}/{passed + failed} checks passed ===");
return failed == 0 ? 0 : 1;

// A UDP relay that can cut the path. It forwards both ways until `darkAfter` datagrams from the
// server are through, then drops everything in both directions for `darkFor`, noting what the
// server sends meanwhile: from `grace` on, none of it can be an answer, only a timer firing.
sealed class DarkRelay : IDisposable
{
    private readonly UdpClient               _front = new(new IPEndPoint(IPAddress.Loopback, 0)); // the client talks to this
    private readonly UdpClient               _back;                                             // this talks to the server
    private readonly CancellationTokenSource _stop  = new();
    private readonly TaskCompletionSource    _wentDark = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly int                     _darkAfter;
    private readonly long                    _darkTicks;
    private readonly long                    _graceTicks;
    private IPEndPoint?                      _client;
    private int                              _forwarded;
    private int                              _sentWhileDark;
    private long                             _darkFrom;     // Stopwatch timestamp; 0 until the cut
    private long                             _firstOwnSend; // Stopwatch timestamp; 0 until one arrives

    public DarkRelay(IPEndPoint server, int darkAfter, TimeSpan darkFor, TimeSpan grace)
    {
        _back = new UdpClient(server.AddressFamily);
        _back.Connect(server);
        _darkAfter  = darkAfter;
        _darkTicks  = (long) (darkFor.TotalSeconds * Stopwatch.Frequency);
        _graceTicks = (long) (grace.TotalSeconds   * Stopwatch.Frequency);
        _ = Task.Run(ClientToServer);
        _ = Task.Run(ServerToClient);
    }

    public int  Port          => ((IPEndPoint) _front.Client.LocalEndPoint!).Port;
    public Task WentDark      => _wentDark.Task;
    public int  SentWhileDark => Volatile.Read(ref _sentWhileDark);

    public TimeSpan? FirstOwnSend =>
        Volatile.Read(ref _firstOwnSend) is var at and not 0 ? Stopwatch.GetElapsedTime(_darkFrom, at) : null;

    private bool IsDark(long now)
    {
        long from = Volatile.Read(ref _darkFrom);
        return from != 0 && now - from < _darkTicks;
    }

    private async Task ClientToServer()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult datagram = await _front.ReceiveAsync(_stop.Token);
                _client = datagram.RemoteEndPoint;
                if (!IsDark(Stopwatch.GetTimestamp()))
                    await _back.SendAsync(datagram.Buffer, _stop.Token);
            }
            catch (SocketException) { } // Windows reports an earlier ICMP "port unreachable" here
            catch (Exception)       { return; }
        }
    }

    private async Task ServerToClient()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult datagram = await _back.ReceiveAsync(_stop.Token);
                long now = Stopwatch.GetTimestamp();
                if (IsDark(now))
                {
                    Interlocked.Increment(ref _sentWhileDark);
                    if (now - _darkFrom >= _graceTicks)
                        Interlocked.CompareExchange(ref _firstOwnSend, now, 0);
                    continue;
                }
                if (_client is { } client)
                    await _front.SendAsync(datagram.Buffer, client, _stop.Token);
                if (++_forwarded == _darkAfter)
                {
                    Volatile.Write(ref _darkFrom, Stopwatch.GetTimestamp());
                    _wentDark.TrySetResult();
                }
            }
            catch (SocketException) { }
            catch (Exception)       { return; }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _front.Dispose();
        _back.Dispose();
        _stop.Dispose();
    }
}
