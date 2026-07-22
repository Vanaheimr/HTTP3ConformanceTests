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

using System.Text;

using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Die Task-basierte async API (<see cref="Http3Client"/>/<see cref="Http3Server"/>): echte UDP-
/// Sockets über Loopback, Hintergrund-Pump, await-bare Requests — der deterministische Kern bleibt
/// darunter unverändert.
/// </summary>
[TestFixture]
public class Http3AsyncApiTests
{
    [Test]
    public async Task GetAsync_OverRealLoopbackUdp_Returns200()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        await using var server = new Http3Server(cert,
            request => new Http3Response { Status = 200, Body = Encoding.UTF8.GetBytes($"hallo {request.Path}") },
            port: 0);
        server.Start();
        Assert.That(server.Port, Is.GreaterThan(0));

        await using var client = new Http3Client("localhost", server.Port, validation);
        await client.ConnectAsync(TimeSpan.FromSeconds(10));

        Http3Response response = await client.GetAsync("/async");
        Assert.That(response.Status, Is.EqualTo(200));
        Assert.That(response.BodyText, Is.EqualTo("hallo /async"));
        Assert.That(server.ConnectionCount, Is.EqualTo(1));

        await client.CloseAsync();
    }

    [Test]
    public async Task ParallelRequests_OverOneConnection_AllSucceed()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        await using var server = new Http3Server(cert,
            request => new Http3Response { Status = 200, Body = Encoding.UTF8.GetBytes(request.Path) },
            port: 0);
        server.Start();

        await using var client = new Http3Client("localhost", server.Port, validation);
        await client.ConnectAsync(TimeSpan.FromSeconds(10));

        // Mehrere Requests gleichzeitig — die Pump serialisiert den Kern, die Tasks laufen parallel.
        Http3Response[] responses = await Task.WhenAll(
            client.GetAsync("/eins"), client.GetAsync("/zwei"), client.GetAsync("/drei"));

        Assert.That(responses.Select(r => r.Status), Is.All.EqualTo(200));
        Assert.That(responses.Select(r => r.BodyText), Is.EquivalentTo(new[] { "/eins", "/zwei", "/drei" }));
    }

    [Test]
    public async Task PostAsync_EchoesBody()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        await using var server = new Http3Server(cert,
            request => new Http3Response { Status = 200, Body = request.Body },
            port: 0);
        server.Start();

        await using var client = new Http3Client("localhost", server.Port, validation);
        await client.ConnectAsync(TimeSpan.FromSeconds(10));

        byte[] body = Encoding.UTF8.GetBytes("async-POST-Rumpf");
        Http3Response response = await client.PostAsync("/echo", body, "text/plain");
        Assert.That(response.Status, Is.EqualTo(200));
        Assert.That(response.Body, Is.EqualTo(body));
    }

    [Test]
    public async Task ConnectAsync_AgainstDeadPort_ThrowsTimeout()
    {
        // Kein Server: der Handshake kann nie bestätigt werden ⇒ TimeoutException statt Hänger.
        await using var client = new Http3Client("localhost", 1, CertificateValidationOptions.Insecure);
        Assert.ThrowsAsync<TimeoutException>(() => client.ConnectAsync(TimeSpan.FromMilliseconds(500)));
    }

    [Test]
    public async Task QueryAndPerformAsync_GiveSerializedAccessToTheConnection()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        await using var server = new Http3Server(cert, _ => new Http3Response { Status = 204 }, port: 0);
        server.Start();

        await using var client = new Http3Client("localhost", server.Port, validation);
        await client.ConnectAsync(TimeSpan.FromSeconds(10));

        Assert.That(await client.QueryAsync(c => c.HandshakeConfirmed), Is.True);
        // WaitUntilAsync pollt, während die Pump weiterläuft (hier trivial sofort erfüllt).
        Assert.That(await client.WaitUntilAsync(c => c.HandshakeConfirmed, TimeSpan.FromSeconds(1)), Is.True);
    }
}
