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

using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Several clients against ONE server — a path nothing else in this suite covered. Every other
/// real-socket test opens a single <see cref="Http3Client"/>, so "the server serves a second
/// client" was never actually asserted.
/// </summary>
[TestFixture]
public class Http3MultipleClientsTests
{

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private static Http3Server StartServer(ServerCertificate cert)
    {
        var server = new Http3Server(cert, _ => new Http3Response { Status = 200, Body = "ok"u8.ToArray() }, port: 0);
        server.Start();
        return server;
    }

    private static async Task<int> RequestAsync(int port, CertificateValidationOptions validation)
    {
        await using var client = new Http3Client("localhost", port, validation);
        await client.ConnectAsync(ConnectTimeout);
        Http3Response response = await client.GetAsync("/").WaitAsync(RequestTimeout);
        return response.Status;
    }

    [Test]
    public async Task TwoClientsOneAfterTheOther_BothGetServed()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        await using Http3Server server = StartServer(cert);

        Assert.That(await RequestAsync(server.Port, validation), Is.EqualTo(200), "First client.");
        Assert.That(await RequestAsync(server.Port, validation), Is.EqualTo(200),
                    "Second client — the one the scratch probe could not get through.");
    }

    [Test]
    public async Task FiveClientsOneAfterTheOther_AllGetServed()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        await using Http3Server server = StartServer(cert);

        for (int i = 0; i < 5; i++)
            Assert.That(await RequestAsync(server.Port, validation), Is.EqualTo(200), $"Client {i + 1}.");

        Assert.That(server.ConnectionsRefused, Is.Zero);
    }

    [Test]
    public async Task FourConcurrentClients_AllGetServed()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        await using Http3Server server = StartServer(cert);

        int[] statuses = await Task.WhenAll(Enumerable.Range(0, 4)
                                                      .Select(_ => RequestAsync(server.Port, validation)));

        Assert.That(statuses, Is.All.EqualTo(200));
        Assert.That(server.ConnectionsRefused, Is.Zero);
    }

    [Test]
    public async Task TwoClientsAtOnce_StayIndependent()
    {
        // Both connections are live at the same time and interleave their requests — the demux by
        // connection ID has to keep them apart rather than routing one client's packets into the
        // other's connection.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        await using var server = new Http3Server(cert,
            request => new Http3Response { Status = 200, Body = System.Text.Encoding.UTF8.GetBytes(request.Path) },
            port: 0);
        server.Start();

        await using var a = new Http3Client("localhost", server.Port, validation);
        await using var b = new Http3Client("localhost", server.Port, validation);
        await a.ConnectAsync(ConnectTimeout);
        await b.ConnectAsync(ConnectTimeout);

        for (int round = 0; round < 3; round++)
        {
            Http3Response fromA = await a.GetAsync($"/a{round}").WaitAsync(RequestTimeout);
            Http3Response fromB = await b.GetAsync($"/b{round}").WaitAsync(RequestTimeout);
            Assert.That(System.Text.Encoding.UTF8.GetString(fromA.Body), Is.EqualTo($"/a{round}"));
            Assert.That(System.Text.Encoding.UTF8.GetString(fromB.Body), Is.EqualTo($"/b{round}"));
        }
    }

}
