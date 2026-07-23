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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Measurement harness of phase 9 (zero-alloc): measures time and allocations of the in-process hot
/// paths with <see cref="GC.GetAllocatedBytesForCurrentThread"/> (the pump is single-threaded ⇒ exact).
/// The numbers land in the Assert.Pass text; DELIBERATELY generous upper bounds (factor ≥ 2 above
/// the actual) serve as regression guards so the tests never become flaky.
/// </summary>
[TestFixture]
public class PerformanceBenchTests
{
    private const int BigBodySize = 300_000;
    private const int SmallRequestCount = 50;

    [Test]
    public void Bench_LargeDownload_TimeAndAllocations()
    {
        (Http3ClientConnection client, Http3ServerConnection server, ServerCertificate cert) = Pair(BigBody);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        // Warm-up (JIT + static tables) with a small request.
        RunRequest(client, server, "/small");

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var watch = Stopwatch.StartNew();
        Http3Response response = RunRequest(client, server, "/big");
        watch.Stop();
        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

        Assert.That(response.Body, Has.Length.EqualTo(BigBodySize));
        // Regression guard: actual after the zero-alloc conversion is ~7 MiB (previously ~51 MiB) — the
        // limit catches a return to List<byte> shifting but leaves plenty of headroom for JIT/GC noise.
        Assert.That(allocated, Is.LessThan(20L * 1024 * 1024),
            $"300-KB download allocated {allocated / 1024.0 / 1024.0:F1} MiB — regression in the zero-alloc path?");
        Assert.Pass($"300-KB download: {watch.Elapsed.TotalMilliseconds:F1} ms, " +
                    $"{allocated / 1024.0 / 1024.0:F2} MiB allocated ({allocated / (double)BigBodySize:F1} B/payload byte).");
    }

    [Test]
    public void Bench_ManySmallRequests_TimeAndAllocations()
    {
        (Http3ClientConnection client, Http3ServerConnection server, ServerCertificate cert) = Pair(BigBody);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        RunRequest(client, server, "/small"); // warm-up

        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var watch = Stopwatch.StartNew();
        for (int i = 0; i < SmallRequestCount; i++)
            RunRequest(client, server, "/small");
        watch.Stop();
        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

        Assert.That(allocated / SmallRequestCount, Is.LessThan(600L * 1024),
            $"A small request allocated {allocated / SmallRequestCount / 1024.0:F1} KiB on average — regression?");
        Assert.Pass($"{SmallRequestCount} small requests: {watch.Elapsed.TotalMilliseconds:F1} ms total, " +
                    $"{allocated / SmallRequestCount / 1024.0:F1} KiB/request allocated.");
    }

    // ---- Helpers --------------------------------------------------------------------------

    private static readonly byte[] BigBodyBytes = CreateBody();

    private static byte[] CreateBody()
    {
        byte[] body = new byte[BigBodySize];
        for (int i = 0; i < body.Length; i++)
            body[i] = (byte)(i * 31);
        return body;
    }

    private static Http3Response BigBody(Http3Request request)
        => new() { Status = 200, Body = request.Path == "/big" ? BigBodyBytes : [1, 2, 3] };

    private static (Http3ClientConnection, Http3ServerConnection, ServerCertificate) Pair(Func<Http3Request, Http3Response> handler)
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var server = new Http3ServerConnection(cert, handler);
        var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();
        return (client, server, cert);
    }

    private static Http3Response RunRequest(Http3ClientConnection client, Http3ServerConnection server, string path)
    {
        ulong id = client.SendRequest(Http3Request.Get("localhost", path));
        Http3Response? response = null;
        for (int round = 0; round < 4000 && response is null; round++)
        {
            Pump(client, server);
            client.TryGetResponse(id, out response);
        }
        Assert.That(response, Is.Not.Null, "The response did not arrive.");
        return response!;
    }

    private static void Pump(Http3ClientConnection client, Http3ServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
