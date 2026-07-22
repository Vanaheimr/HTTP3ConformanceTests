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

using System.Security.Cryptography;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests für Stateless Reset (RFC 9000 §10.3): den Paketaufbau sowie die Erkennung anhand des vom Server
/// per Transport-Parameter angekündigten Stateless-Reset-Tokens.
/// </summary>
public class StatelessResetTests
{
    [Fact]
    public void Build_EndsWithToken_AndLooksLikeAShortHeaderPacket()
    {
        byte[] token = RandomNumberGenerator.GetBytes(StatelessReset.TokenLength);
        byte[] packet = StatelessReset.Build(token, totalLength: 41);

        Assert.Equal(41, packet.Length);
        Assert.True(StatelessReset.EndsWith(packet, token));
        Assert.Equal(0, packet[0] & 0x80);    // Header Form 0 (Short Header)
        Assert.Equal(0x40, packet[0] & 0x40); // Fixed Bit gesetzt
    }

    [Fact]
    public void Build_RejectsWrongTokenLength()
        => Assert.Throws<ArgumentException>(() => StatelessReset.Build(new byte[8]));

    private static (QuicClientConnection client, QuicServerConnection server) Handshaken(ServerCertificate cert)
    {
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var client = new QuicClientConnection("localhost", certificateValidation: validation);
        var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
        }
        Assert.True(client.HandshakeConfirmed);
        return (client, server);
    }

    [Fact]
    public void StatelessReset_WithKnownToken_TerminatesConnection()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        // Der Server kündigt seinen Stateless-Reset-Token per Transport-Parameter an; der Client hat ihn.
        byte[]? token = client.PeerTransportParameters?.StatelessResetTokenValue;
        Assert.NotNull(token);

        // Ein Paket, das (statt entschlüsselbar zu sein) mit diesem Token endet, ist ein Stateless Reset.
        byte[] reset = StatelessReset.Build(token!);
        client.ProcessDatagram(reset);

        Assert.True(client.StatelessResetReceived, "Der Client muss den Stateless Reset erkennen.");
        Assert.True(client.IsDraining, "Nach einem Stateless Reset geht die Verbindung in Draining.");
    }

    [Fact]
    public void TokenGenerator_IsDeterministic_PerCidAndSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var a = new StatelessResetTokenGenerator(secret);
        var b = new StatelessResetTokenGenerator(secret);
        byte[] cid1 = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] cid2 = [1, 2, 3, 4, 5, 6, 7, 9];

        Assert.Equal(a.ComputeToken(cid1), b.ComputeToken(cid1));    // gleiches Geheimnis+CID ⇒ gleiches Token
        Assert.NotEqual(a.ComputeToken(cid1), a.ComputeToken(cid2)); // andere CID ⇒ anderes Token
        Assert.Equal(StatelessReset.TokenLength, a.ComputeToken(cid1).Length);
    }

    [Fact]
    public void BuildResponse_IgnoresLongHeaderAndTinyPackets()
    {
        var gen = new StatelessResetTokenGenerator();
        byte[] longHeader = new byte[30];
        longHeader[0] = 0xC0; // Long Header (Initial) ⇒ neue Verbindung, kein Reset
        Assert.Null(StatelessReset.BuildResponse(longHeader, localCidLength: 8, gen));

        byte[] tiny = new byte[StatelessReset.MinLength];
        tiny[0] = 0x40; // Short Header, aber ≤ 21 Byte ⇒ kein (kleinerer) Reset möglich
        Assert.Null(StatelessReset.BuildResponse(tiny, localCidLength: 8, gen));
    }

    [Fact]
    public void BuildResponse_ProducesSmallerResetEndingWithCidToken()
    {
        var gen = new StatelessResetTokenGenerator();
        byte[] cid = [9, 8, 7, 6, 5, 4, 3, 2];
        byte[] incoming = new byte[29];
        incoming[0] = 0x40;
        cid.CopyTo(incoming, 1);

        byte[]? reset = StatelessReset.BuildResponse(incoming, localCidLength: 8, gen);
        Assert.NotNull(reset);
        Assert.True(reset!.Length < incoming.Length, "Der Reset muss kleiner sein als der Auslöser (Loop-Vermeidung).");
        Assert.True(StatelessReset.EndsWith(reset, gen.ComputeToken(cid)));
    }

    [Fact]
    public void StatelessResponder_WithSharedSecret_ProducesResetTheClientRecognizes()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var gen = new StatelessResetTokenGenerator(secret);

        // Der Server leitet sein Token aus der CID ab ⇒ der Client speichert token = HMAC(secret, serverCID).
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert, statelessResetTokens: gen);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }
        Assert.True(client.HandshakeConfirmed);

        // Ein zustandsloser Endpoint mit DEMSELBEN Geheimnis empfängt ein 1-RTT-Paket an die Server-CID und
        // rechnet das Token aus der DCID neu → Stateless Reset. (Simuliert einen Server nach Zustandsverlust.)
        ConnectionId serverCid = client.DestinationConnectionId;
        byte[] packetToLostServer = FakeShortHeaderTo(serverCid);
        byte[]? reset = StatelessReset.BuildResponse(packetToLostServer, serverCid.Length, gen);
        Assert.NotNull(reset);

        client.ProcessDatagram(reset!);
        Assert.True(client.StatelessResetReceived, "Der Client muss den Stateless Reset des zustandslosen Endpoints erkennen.");
        Assert.True(client.IsDraining);
    }

    private static byte[] FakeShortHeaderTo(ConnectionId dcid)
    {
        // Ein 1-RTT-förmiges Paket (> 21 Byte) an die gegebene DCID, sonst zufällig.
        byte[] packet = RandomNumberGenerator.GetBytes(1 + dcid.Length + 20);
        packet[0] = 0x40; // Header Form 0 (Short), Fixed Bit 1
        dcid.Span.CopyTo(packet.AsSpan(1));
        return packet;
    }

    [Fact]
    public void UnrecognizedToken_IsNotTreatedAsStatelessReset()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        // Ein „Reset" mit unbekanntem (hier: Null-)Token darf die Verbindung nicht beenden.
        byte[] reset = StatelessReset.Build(new byte[StatelessReset.TokenLength]);
        client.ProcessDatagram(reset);

        Assert.False(client.StatelessResetReceived);
        Assert.False(client.IsDraining);
    }
}
