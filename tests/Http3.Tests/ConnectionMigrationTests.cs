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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests der Pfadvalidierung (RFC 9000 §8.2) – dem Kern-Primitiv der Connection Migration (§9):
/// PATH_CHALLENGE senden, passendes PATH_RESPONSE erwarten.
/// </summary>
public class ConnectionMigrationTests
{
    private static (QuicClientConnection client, QuicServerConnection server) Handshaken(ServerCertificate cert)
    {
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var client = new QuicClientConnection("localhost", certificateValidation: validation);
        var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.True(client.HandshakeConfirmed);
        Pump(client, server);
        return (client, server);
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    [Fact]
    public void PathValidation_ClientInitiates_ServerResponds_IsValidated()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        Assert.False(client.PathValidated);

        client.InitiatePathValidation(); // sendet PATH_CHALLENGE
        Assert.True(client.PathValidationPending);

        for (int round = 0; round < 5; round++)
            Pump(client, server); // Server spiegelt via PATH_RESPONSE zurück

        Assert.True(client.PathValidated, "Ein passendes PATH_RESPONSE muss den Pfad validieren.");
        Assert.False(client.PathValidationPending);
    }

    [Fact]
    public void PathValidation_ServerInitiates_ClientResponds_IsValidated()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        server.InitiatePathValidation();
        Assert.True(server.PathValidationPending);

        for (int round = 0; round < 5; round++)
            Pump(client, server);

        Assert.True(server.PathValidated);
    }

    [Fact]
    public void PathValidation_WithoutResponse_Expires_AndDoesNotValidate()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        client.InitiatePathValidation();
        Assert.True(client.PathValidationPending);

        // Ohne Austausch verstreicht die Validierungsfrist (3·PTO, in-process winzig).
        Thread.Sleep(300);
        client.CheckIdleTimeout(); // treibt den Ablauf

        Assert.False(client.PathValidationPending, "Ohne PATH_RESPONSE muss die Validierung verfallen.");
        Assert.False(client.PathValidated);
    }
}
