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

using System.Threading;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Integrationstest für Keep-Alive via PING (RFC 9000 §10.1.2): regelmäßige PINGs halten eine Verbindung
/// über einen kurzen Idle-Timeout hinaus offen, wo sie sonst still geschlossen würde.
/// </summary>
[TestFixture]
public class KeepAliveTests
{
    [Test]
    public void KeepAlivePings_KeepConnectionAlive_PastTheIdleTimeout()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // Server kündigt einen kurzen Idle-Timeout an (250 ms); der Client sendet alle 60 ms ein Keep-Alive-PING.
        var serverParams = new TransportParameters { MaxIdleTimeoutMs = 250 };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert, serverParams);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True, "Handshake muss zustande kommen.");

        client.KeepAliveInterval = TimeSpan.FromMilliseconds(60);

        // Deutlich länger als der Idle-Timeout (250 ms) verstreichen lassen, dabei regelmäßig pumpen.
        for (int round = 0; round < 18; round++)
        {
            Pump(client, server);
            client.CheckIdleTimeout();
            server.CheckIdleTimeout();
            Thread.Sleep(30); // ~540 ms gesamt ⇒ > 250 ms Idle-Timeout
        }

        Assert.That(server.IsIdleTimedOut, Is.False, "Keep-Alive-PINGs müssen den Server-Idle-Timeout verhindern.");
        Assert.That(client.IsIdleTimedOut, Is.False, "Der Client bleibt durch die PINGs (und die ACKs des Servers) aktiv.");
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
