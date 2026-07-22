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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Session Resumption / PSK (RFC 8446 §2.2/§4.6.1) auf TLS-Ebene, in-process: Verbindung 1 führt einen
/// vollen Handshake und der Server stellt ein NewSessionTicket aus; Verbindung 2 spielt das Ticket im
/// pre_shared_key zurück, der Server prüft den Binder und resümiert (ohne Zertifikat). Prüft zugleich die
/// graceful Fallback-Wege, wenn der Server das Ticket nicht kennt.
/// </summary>
public class ResumptionTests
{
    private static readonly byte[] Tp = [0x0f, 0x00];

    [Fact]
    public void Client_ResumesWithPsk_ServerSkipsCertificate_AndSecretsMatch()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var trusting = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // Verbindung 1: voller Handshake; der Server stellt anschließend ein Ticket aus.
        var client1 = new TlsClientHandshake("localhost", Tp, certificateValidation: trusting);
        using var server1 = new TlsServerHandshake(cert, Tp, resumptionCache: cache);
        RunHandshake(client1, server1);
        Assert.True(client1.ServerCertificateValid);
        Assert.False(client1.ResumptionAccepted);

        // NewSessionTicket kommt post-Handshake auf Application-Level – einmal nachpumpen.
        Pump(server1, client1);
        Assert.NotEmpty(client1.NewSessionTickets);
        ResumptionTicket ticket = client1.NewSessionTickets[0];
        client1.Dispose();

        // Verbindung 2: Resumption mit dem Ticket.
        var client2 = new TlsClientHandshake("localhost", Tp, certificateValidation: trusting, resumptionTicket: ticket);
        using var server2 = new TlsServerHandshake(cert, Tp, resumptionCache: cache);
        RunHandshake(client2, server2);

        Assert.True(client2.ResumptionAccepted, "Client muss die PSK-Annahme (selected_identity) erkennen.");
        Assert.True(server2.ResumptionAccepted, "Server muss den PSK-Binder akzeptiert haben.");
        Assert.False(client2.ServerCertificateValid); // Resumption ⇒ kein Zertifikat
        AssertMatchingSecrets(client2, server2);
        client2.Dispose();
    }

    [Fact]
    public void UnknownTicket_FallsBackToFullHandshake_WithCertificate()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var cache = new ServerResumptionCache();
        var trusting = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        var client1 = new TlsClientHandshake("localhost", Tp, certificateValidation: trusting);
        using var server1 = new TlsServerHandshake(cert, Tp, resumptionCache: cache);
        RunHandshake(client1, server1);
        Pump(server1, client1);
        ResumptionTicket ticket = client1.NewSessionTickets[0];
        client1.Dispose();

        // Zweiter Server mit LEEREM Store ⇒ kennt das Ticket nicht ⇒ voller Handshake mit Zertifikat.
        var client2 = new TlsClientHandshake("localhost", Tp, certificateValidation: trusting, resumptionTicket: ticket);
        using var server2 = new TlsServerHandshake(cert, Tp, resumptionCache: new ServerResumptionCache());
        RunHandshake(client2, server2);

        Assert.False(client2.ResumptionAccepted);
        Assert.False(server2.ResumptionAccepted);
        Assert.True(client2.ServerCertificateValid, "Ohne Resumption muss das Zertifikat geprüft werden.");
        AssertMatchingSecrets(client2, server2);
        client2.Dispose();
    }

    private static void RunHandshake(TlsClientHandshake client, TlsServerHandshake server)
    {
        client.Start();
        for (int round = 0; round < 10 && !(client.IsComplete && server.IsComplete); round++)
        {
            Pump(client, server);
            Pump(server, client);
        }
        Assert.True(client.IsComplete, "Client-Handshake unvollständig.");
        Assert.True(server.IsComplete, "Server-Handshake unvollständig.");
    }

    private static void AssertMatchingSecrets(ITlsHandshake client, ITlsHandshake server)
    {
        Assert.Equal(client.ApplicationSecrets!.ClientApplicationTrafficSecret,
                     server.ApplicationSecrets!.ClientApplicationTrafficSecret);
        Assert.Equal(client.ApplicationSecrets.ServerApplicationTrafficSecret,
                     server.ApplicationSecrets.ServerApplicationTrafficSecret);
    }

    private static void Pump(ITlsHandshake from, ITlsHandshake to)
    {
        while (from.TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data))
            to.ProvideCrypto(level, data);
    }
}
