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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests des Anti-Amplification-Limits (RFC 9000 §8.1): Vor der Adressvalidierung darf der Server nicht
/// mehr als das Dreifache der empfangenen Bytes senden; der Client ist per Konstruktion nicht limitiert.
/// </summary>
public class AntiAmplificationTests
{
    private static (QuicClientConnection client, QuicServerConnection server) NewPair(ServerCertificate cert)
    {
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        return (new QuicClientConnection("localhost", certificateValidation: validation), new QuicServerConnection(cert));
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    [Fact]
    public void Client_IsValidatedByConstruction_ServerIsNot()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = NewPair(cert);
        using var _ = client;
        using var __ = server;

        Assert.True(client.AddressValidated);   // der Client limitiert sich nicht
        Assert.False(server.AddressValidated);   // der Server erst nach Adressvalidierung
    }

    [Fact]
    public void Server_NeverSendsMoreThanThreeTimesReceived_BeforeAddressValidation()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = NewPair(cert);
        using var _ = client;
        using var __ = server;
        client.Start();

        // Genau EIN Client-Initial an den Server geben; danach NICHTS mehr empfangen.
        long received = 0;
        foreach (byte[] dg in client.GetDatagramsToSend())
        {
            received += dg.Length;
            server.ProcessDatagram(dg);
        }

        // Über mehrere Sende-Gelegenheiten (ohne weiteren Empfang) darf der Server das 3×-Limit nie überschreiten.
        long sent = 0;
        for (int i = 0; i < 10; i++)
            foreach (byte[] dg in server.GetDatagramsToSend())
                sent += dg.Length;

        Assert.False(server.AddressValidated); // ohne Handshake-Paket des Clients weiterhin unvalidiert
        Assert.True(sent > 0, "Der Server sendet seinen (begrenzten) Flight.");
        Assert.True(sent <= 3 * received, $"Anti-Amplification verletzt: {sent} > 3×{received}.");
    }

    [Fact]
    public void Server_BecomesValidated_AfterCompletingHandshake()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = NewPair(cert);
        using var _ = client;
        using var __ = server;
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);

        Assert.True(client.HandshakeConfirmed);
        Assert.True(server.AddressValidated, "Ein empfangenes Handshake-Paket validiert die Client-Adresse.");
    }

    [Fact]
    public void RetryToken_ValidatesAddress_Immediately()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert, requireRetry: true);
        client.Start();

        // Bis der Handshake steht: das gültige Retry-Token hebt das Limit früh auf.
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);

        Assert.True(server.SentRetry);
        Assert.True(server.AddressValidated);
        Assert.True(client.HandshakeConfirmed);
    }
}
