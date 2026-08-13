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
using System.Security.Cryptography;

#endregion

// h3bench: how fast the demo server (samples/H3Server) actually is, over loopback, driven by
// .NET's HttpClient on msquic.
//
// This is NOT a pass/fail harness and tests/run-tests.ps1 does not gate on it. It exists because
// the performance claims in the README — zero-alloc hot paths, UDP batching, window auto-tuning —
// had no number anyone could reproduce, which makes "fast enough" an assumption rather than a
// finding. Now there is a baseline, and any future optimisation has something to beat.
//
// It found two things on its first run, which is the argument for having it:
//
//   * The upload path is an order of magnitude slower than the download path for the same 300 000
//     bytes — ~130 ms per round trip against ~11 ms — and it degrades from there. A later run
//     measured 830 ms and then lost the connection to the idle timeout after 40 of 50 uploads.
//     Receiving large request bodies stalls somewhere that sending them does not.
//   * Throughput falls as concurrency rises: ~62 MiB/s with one request in flight, ~22 MiB/s with
//     32. More streams should not cost that much on loopback.
//
// Neither is a pass/fail matter, which is exactly why they had gone unnoticed: nothing was
// measuring. The numbers below are the baseline both should be judged against from now on.
//
// Read the numbers for what they are. Loopback has no propagation delay and effectively no loss,
// so throughput here measures our packet handling, framing and crypto, not a network. And both
// ends share one machine's cores: the client is msquic, and its cost is inside every number below.
// Comparing two runs of this file is meaningful; comparing it to a datacentre benchmark is not.
//
// Needs the demo host running:  dotnet run --project samples/H3Server -- 4433

string host = Environment.GetEnvironmentVariable("H3_HOST") ?? "localhost";
int    port = int.TryParse(Environment.GetEnvironmentVariable("H3_PORT"), out int p) ? p : 4433;
string root = $"https://{host}:{port}";

if (!System.Net.Quic.QuicConnection.IsSupported)
{
    Console.WriteLine("h3bench: SKIPPED — System.Net.Quic reports no QUIC support on this machine.");
    return 2;
}

// One connection per phase, and no phase above 90 requests.
//
// Not a style choice: the server grants initial_max_streams_bidi = 100 and never sends MAX_STREAMS
// to extend it (RFC 9000 §4.6), so a connection carries exactly 100 requests and then stalls until
// it times out. h3semantics pins that as a failing check; here it would silently turn a throughput
// figure into a measurement of the timeout. Once MAX_STREAMS is implemented, these phases can share
// one connection again and the handshake drops out of the numbers.
HttpClient client = NewClient();

static HttpClient NewClient() =>
    new(new SocketsHttpHandler {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions {
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        }) {
        DefaultRequestVersion = HttpVersion.Version30,
        DefaultVersionPolicy  = HttpVersionPolicy.RequestVersionExact,
        Timeout               = TimeSpan.FromSeconds(60)
    };

void NextPhase()
{
    client.Dispose();
    client = NewClient();
}

async Task<byte[]> Get(string path)
{
    var request = new HttpRequestMessage(HttpMethod.Get, root + path) {
        Version       = HttpVersion.Version30,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact
    };
    HttpResponseMessage response = await client.SendAsync(request);
    return await response.Content.ReadAsByteArrayAsync();
}

async Task<int> Post(string path, byte[] payload)
{
    var request = new HttpRequestMessage(HttpMethod.Post, root + path) {
        Version       = HttpVersion.Version30,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Content       = new ByteArrayContent(payload)
    };
    HttpResponseMessage response = await client.SendAsync(request);
    return (await response.Content.ReadAsByteArrayAsync()).Length;
}

static string Rate(long bytes, TimeSpan elapsed) =>
    $"{bytes / 1024.0 / 1024.0 / Math.Max(elapsed.TotalSeconds, 1e-9),8:F1} MiB/s";

Console.WriteLine($"=== h3bench — {root} (client: .NET HttpClient over msquic) ===");
Console.WriteLine($"    {Environment.ProcessorCount} logical cores, {Environment.OSVersion}\n");

// Cold start is real but it is not the steady state, and mixing the two produces a number that
// describes neither. The first request against a freshly started server has been seen to take 30x
// the steady-state figure — JIT, the certificate, the first key schedule.
Console.WriteLine("Warming up (handshake, JIT, first key schedule) …");
for (int i = 0; i < 5; i++)
    await Get("/");
Console.WriteLine();

Console.WriteLine("=== Download — GET /big, 300 000 bytes ===");
{
    const int iterations = 50;
    byte[] first = await Get("/big");
    var stopwatch = Stopwatch.StartNew();
    long total = 0;
    for (int i = 0; i < iterations; i++)
        total += (await Get("/big")).Length;
    stopwatch.Stop();
    Console.WriteLine($"  {iterations} x {first.Length,7} bytes   {Rate(total, stopwatch.Elapsed)}"
                      + $"   {stopwatch.Elapsed.TotalMilliseconds / iterations,7:F2} ms/request");
}

NextPhase();
Console.WriteLine("\n=== Upload — POST /echo, 300 000 bytes (echoed back, so both directions) ===");
{
    const int iterations = 50;
    byte[] payload = new byte[300_000];
    RandomNumberGenerator.Fill(payload);
    var stopwatch = Stopwatch.StartNew();
    long total = 0;
    int done = 0;
    try
    {
        for (int i = 0; i < iterations; i++)
        {
            total += await Post("/echo", payload);
            done++;
        }
    }
    catch (Exception e)
    {
        // A benchmark that dies with a stack trace reports nothing at all. Say which iteration
        // broke and keep the numbers gathered up to that point — that is the finding.
        Console.WriteLine($"  ! stopped after {done}/{iterations} uploads: {(e.InnerException ?? e).Message}");
    }
    stopwatch.Stop();
    // Every byte crosses the wire twice, so the transferred volume is 2x the payload.
    if (done > 0)
        Console.WriteLine($"  {done} x {payload.Length,7} bytes   {Rate(total * 2, stopwatch.Elapsed)}"
                          + $"   {stopwatch.Elapsed.TotalMilliseconds / done,7:F2} ms/round trip");
}

NextPhase();
Console.WriteLine("\n=== Latency — GET / , 90 sequential requests on one connection ===");
{
    const int iterations = 90;
    var samples = new double[iterations];
    for (int i = 0; i < iterations; i++)
    {
        long start = Stopwatch.GetTimestamp();
        await Get("/");
        samples[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
    }
    Array.Sort(samples);
    static double Percentile(double[] sorted, double q) => sorted[(int) Math.Clamp(q * sorted.Length, 0, sorted.Length - 1)];
    Console.WriteLine($"  p50 {Percentile(samples, 0.50),6:F2} ms   p90 {Percentile(samples, 0.90),6:F2} ms"
                      + $"   p99 {Percentile(samples, 0.99),6:F2} ms   max {samples[^1],6:F2} ms");
    Console.WriteLine($"  {iterations / samples.Sum() * 1000,8:F0} requests/s sustained");
}

Console.WriteLine("\n=== Concurrency — GET /big with N requests in flight ===");
foreach (int concurrency in (int[]) [1, 2, 4, 8, 16, 32])
{
    NextPhase(); // 32 requests per level would cross the 100-stream ceiling by the fourth level
    const int perLevel = 32;
    var stopwatch = Stopwatch.StartNew();
    long total = 0;
    var inFlight = new List<Task<byte[]>>();
    for (int i = 0; i < perLevel; i++)
    {
        inFlight.Add(Get("/big"));
        if (inFlight.Count == concurrency)
        {
            foreach (byte[] body in await Task.WhenAll(inFlight))
                total += body.Length;
            inFlight.Clear();
        }
    }
    foreach (byte[] body in await Task.WhenAll(inFlight))
        total += body.Length;
    stopwatch.Stop();
    Console.WriteLine($"  {concurrency,2} in flight   {Rate(total, stopwatch.Elapsed)}"
                      + $"   {stopwatch.Elapsed.TotalMilliseconds / perLevel,7:F2} ms/request");
}

// Allocation belongs to whichever process you measure, and this one is the client. Our server runs
// next door, so its allocation profile is not visible from here — the README's "300 KB download
// 51 -> 7 MiB" figure was measured inside our own client and needs a profiler, not a stopwatch.
// What this number does say: the harness itself is not what the throughput figures above measure.
Console.WriteLine($"\n  (client-side allocation over the whole run: "
                  + $"{GC.GetTotalAllocatedBytes(precise: false) / 1024.0 / 1024.0:F1} MiB — msquic + HttpClient, not our server)");

Console.WriteLine("\n=== h3bench done — no pass/fail, these are numbers to beat ===");
return 0;
