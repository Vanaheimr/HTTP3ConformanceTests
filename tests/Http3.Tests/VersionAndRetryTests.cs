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

using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests für Version Negotiation (RFC 9000 §6) und Retry / Adressvalidierung (RFC 9000 §8.1, §17.2.5;
/// RFC 9001 §5.8): Paket-Round-Trips sowie In-Process-Szenarien Client ↔ eigener Server.
/// </summary>
public class VersionAndRetryTests
{
    private const uint V1 = 0x0000_0001;

    private static ConnectionId Cid(params byte[] bytes) => new(bytes);

    [Fact]
    public void VersionNegotiation_RoundTrips()
    {
        ConnectionId dcid = Cid(1, 2, 3, 4);
        ConnectionId scid = Cid(9, 8, 7);
        byte[] packet = VersionNegotiationPacket.Build(dcid, scid, [V1, 0xff00_001d]);

        Assert.True(VersionNegotiationPacket.TryParse(packet, out ConnectionId d, out ConnectionId s, out List<uint> versions));
        Assert.Equal(dcid.Span.ToArray(), d.Span.ToArray());
        Assert.Equal(scid.Span.ToArray(), s.Span.ToArray());
        Assert.Equal([V1, 0xff00_001d], versions);
    }

    [Fact]
    public void RetryPacket_RoundTrips_AndIntegrityTagVerifies()
    {
        ConnectionId dcid = Cid(0xc0, 0xc1);       // = Client-SCID
        ConnectionId scid = Cid(0x51, 0x52, 0x53); // = neue Server-SCID
        ConnectionId originalDcid = Cid(0xd0, 0xd1, 0xd2, 0xd3);
        byte[] token = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];

        byte[] packet = RetryPacket.Build(V1, dcid, scid, token, originalDcid);

        Assert.True(RetryPacket.TryParse(packet, out uint version, out ConnectionId d, out ConnectionId s, out byte[] t, out byte[] tag));
        Assert.Equal(V1, version);
        Assert.Equal(dcid.Span.ToArray(), d.Span.ToArray());
        Assert.Equal(scid.Span.ToArray(), s.Span.ToArray());
        Assert.Equal(token, t);
        Assert.Equal(16, tag.Length);

        Assert.True(RetryPacket.Verify(packet, originalDcid), "Integrity Tag muss gegen die richtige ODCID stimmen.");
        Assert.False(RetryPacket.Verify(packet, Cid(0xff, 0xff)), "Falsche ODCID muss den Tag scheitern lassen.");
    }

    [Fact]
    public void VersionNegotiation_ClientWithUnsupportedVersion_ReceivesOfferedVersions()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        // Client kündigt eine (erfundene) Version an, die der Server nicht unterstützt.
        using var client = new QuicClientConnection("localhost", version: 0x1a2a_3a4a);
        using var server = new QuicServerConnection(cert); // unterstützt nur v1
        client.Start();

        // Ein Umlauf: Client-Initial (bogus Version) → Server antwortet mit VN → Client verarbeitet es.
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);

        Assert.True(client.VersionNegotiationReceived, "Client muss ein Version-Negotiation-Paket erhalten haben.");
        Assert.Contains(V1, client.OfferedVersions);
        Assert.False(client.HandshakeConfirmed);
    }

    [Fact]
    public void VersionNegotiation_IncludesReservedGreaseVersion()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        using var client = new QuicClientConnection("localhost", version: 0x1a2a_3a4a);
        using var server = new QuicServerConnection(cert);
        client.Start();

        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);

        byte[]? vn = server.GetDatagramsToSend().FirstOrDefault();
        Assert.NotNull(vn);
        Assert.True(VersionNegotiationPacket.TryParse(vn!, out _, out _, out List<uint> versions));
        Assert.Contains(V1, versions);
        // Eine reservierte Version im Muster 0x?a?a?a?a (RFC 9000 §6.3) beugt Ossifizierung vor.
        Assert.Contains(versions, v => (v & 0x0F0F_0F0Fu) == 0x0A0A_0A0Au);
    }

    [Fact]
    public void VersionNegotiation_NotSent_ForDatagramSmallerThan1200()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        using var server = new QuicServerConnection(cert);

        // Ein winziges Long-Header-Paket mit nicht unterstützter Version (0x1a2a3a4a), 4-Byte-CIDs → 15 Byte.
        byte[] tiny =
        [
            0xC0, 0x1a, 0x2a, 0x3a, 0x4a,   // Long Header (Initial) + Version
            4, 0xD0, 0xD1, 0xD2, 0xD3,      // DCID-Länge + DCID
            4, 0x50, 0x51, 0x52, 0x53,      // SCID-Länge + SCID
        ];
        server.ProcessDatagram(tiny);

        // RFC 9000 §6.1/§14.1: auf ein Datagramm < 1200 Byte darf KEIN VN gesendet werden (Anti-Amplification).
        Assert.Empty(server.GetDatagramsToSend());
    }

    [Fact]
    public void Retry_ClientReattemptsWithToken_AndCompletesHandshake()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert, requireRetry: true);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
        }

        Assert.True(server.SentRetry, "Server muss ein Retry zur Adressvalidierung gesendet haben.");
        Assert.True(client.RetryHandled, "Client muss das Retry verarbeitet und den ClientHello erneut gesendet haben.");
        Assert.True(client.HandshakeConfirmed, "Der Handshake muss trotz Retry abschließen.");
        Assert.True(server.HandshakeComplete);

        // Der Server muss die ursprüngliche DCID als Transport-Parameter zurückgemeldet haben (RFC 9000 §7.3).
        Assert.NotNull(client.PeerTransportParameters);
        Assert.NotNull(client.PeerTransportParameters!.RetrySourceConnectionIdValue);
    }
}
