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
// Or just let tests/run-tests.ps1 start it.

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
// The sizes straddle the interesting boundaries: below one packet, above the MTU, above the initial
// 64 KiB stream window (so the server must extend credit mid-upload), and well beyond it.
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

Console.WriteLine($"\n=== {passed}/{passed + failed} checks passed ===");
return failed == 0 ? 0 : 1;
