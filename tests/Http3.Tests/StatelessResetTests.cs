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
[TestFixture]
public class StatelessResetTests
{
    [Test]
    public void Build_EndsWithToken_AndLooksLikeAShortHeaderPacket()
    {
        byte[] token = RandomNumberGenerator.GetBytes(StatelessReset.TokenLength);
        byte[] packet = StatelessReset.Build(token, totalLength: 41);

        Assert.That(packet.Length, Is.EqualTo(41));
        Assert.That(StatelessReset.EndsWith(packet, token), Is.True);
        Assert.That(packet[0] & 0x80, Is.EqualTo(0));    // Header Form 0 (Short Header)
        Assert.That(packet[0] & 0x40, Is.EqualTo(0x40)); // Fixed Bit gesetzt
    }

    [Test]
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
        Assert.That(client.HandshakeConfirmed, Is.True);
        return (client, server);
    }

    [Test]
    public void StatelessReset_WithKnownToken_TerminatesConnection()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        // Der Server kündigt seinen Stateless-Reset-Token per Transport-Parameter an; der Client hat ihn.
        byte[]? token = client.PeerTransportParameters?.StatelessResetTokenValue;
        Assert.That(token, Is.Not.Null);

        // Ein Paket, das (statt entschlüsselbar zu sein) mit diesem Token endet, ist ein Stateless Reset.
        byte[] reset = StatelessReset.Build(token!);
        client.ProcessDatagram(reset);

        Assert.That(client.StatelessResetReceived, Is.True, "Der Client muss den Stateless Reset erkennen.");
        Assert.That(client.IsDraining, Is.True, "Nach einem Stateless Reset geht die Verbindung in Draining.");
    }

    [Test]
    public void TokenGenerator_IsDeterministic_PerCidAndSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var a = new StatelessResetTokenGenerator(secret);
        var b = new StatelessResetTokenGenerator(secret);
        byte[] cid1 = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] cid2 = [1, 2, 3, 4, 5, 6, 7, 9];

        Assert.That(b.ComputeToken(cid1), Is.EqualTo(a.ComputeToken(cid1)));    // gleiches Geheimnis+CID ⇒ gleiches Token
        Assert.That(a.ComputeToken(cid2), Is.Not.EqualTo(a.ComputeToken(cid1))); // andere CID ⇒ anderes Token
        Assert.That(a.ComputeToken(cid1).Length, Is.EqualTo(StatelessReset.TokenLength));
    }

    [Test]
    public void BuildResponse_IgnoresLongHeaderAndTinyPackets()
    {
        var gen = new StatelessResetTokenGenerator();
        byte[] longHeader = new byte[30];
        longHeader[0] = 0xC0; // Long Header (Initial) ⇒ neue Verbindung, kein Reset
        Assert.That(StatelessReset.BuildResponse(longHeader, localCidLength: 8, gen), Is.Null);

        byte[] tiny = new byte[StatelessReset.MinLength];
        tiny[0] = 0x40; // Short Header, aber ≤ 21 Byte ⇒ kein (kleinerer) Reset möglich
        Assert.That(StatelessReset.BuildResponse(tiny, localCidLength: 8, gen), Is.Null);
    }

    [Test]
    public void BuildResponse_ProducesSmallerResetEndingWithCidToken()
    {
        var gen = new StatelessResetTokenGenerator();
        byte[] cid = [9, 8, 7, 6, 5, 4, 3, 2];
        byte[] incoming = new byte[29];
        incoming[0] = 0x40;
        cid.CopyTo(incoming, 1);

        byte[]? reset = StatelessReset.BuildResponse(incoming, localCidLength: 8, gen);
        Assert.That(reset, Is.Not.Null);
        Assert.That(reset!.Length < incoming.Length, Is.True, "Der Reset muss kleiner sein als der Auslöser (Loop-Vermeidung).");
        Assert.That(StatelessReset.EndsWith(reset, gen.ComputeToken(cid)), Is.True);
    }

    [Test]
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
        Assert.That(client.HandshakeConfirmed, Is.True);

        // Ein zustandsloser Endpoint mit DEMSELBEN Geheimnis empfängt ein 1-RTT-Paket an die Server-CID und
        // rechnet das Token aus der DCID neu → Stateless Reset. (Simuliert einen Server nach Zustandsverlust.)
        ConnectionId serverCid = client.DestinationConnectionId;
        byte[] packetToLostServer = FakeShortHeaderTo(serverCid);
        byte[]? reset = StatelessReset.BuildResponse(packetToLostServer, serverCid.Length, gen);
        Assert.That(reset, Is.Not.Null);

        client.ProcessDatagram(reset!);
        Assert.That(client.StatelessResetReceived, Is.True, "Der Client muss den Stateless Reset des zustandslosen Endpoints erkennen.");
        Assert.That(client.IsDraining, Is.True);
    }

    private static byte[] FakeShortHeaderTo(ConnectionId dcid)
    {
        // Ein 1-RTT-förmiges Paket (> 21 Byte) an die gegebene DCID, sonst zufällig.
        byte[] packet = RandomNumberGenerator.GetBytes(1 + dcid.Length + 20);
        packet[0] = 0x40; // Header Form 0 (Short), Fixed Bit 1
        dcid.Span.CopyTo(packet.AsSpan(1));
        return packet;
    }

    [Test]
    public void UnrecognizedToken_IsNotTreatedAsStatelessReset()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        (QuicClientConnection client, QuicServerConnection server) = Handshaken(cert);
        using var _ = client;
        using var __ = server;

        // Ein „Reset" mit unbekanntem (hier: Null-)Token darf die Verbindung nicht beenden.
        byte[] reset = StatelessReset.Build(new byte[StatelessReset.TokenLength]);
        client.ProcessDatagram(reset);

        Assert.That(client.StatelessResetReceived, Is.False);
        Assert.That(client.IsDraining, Is.False);
    }
}
