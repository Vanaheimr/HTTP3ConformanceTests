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
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// HTTP-Datagramme (RFC 9297) über QUIC-DATAGRAM-Frames (RFC 9221): Aushandlung per
/// max_datagram_frame_size (QUIC-TP 0x20) + SETTINGS_H3_DATAGRAM (0x33), Quarter-Stream-ID-Mapping,
/// unzuverlässige Zustellung an Extended-CONNECT-Tunnel.
/// </summary>
[TestFixture]
public class Http3DatagramTests
{
    [Test]
    public void DatagramFrame_RoundTrips_BothTypeVariants()
    {
        // Mit Length-Feld (0x31) — unsere Sendevariante.
        byte[] bytes = FrameParser.Serialize([new DatagramFrame(new byte[] { 1, 2, 3 })]);
        Assert.That(FrameParser.TryParseAll(bytes, out List<Frame> parsed), Is.EqualTo(FrameParseResult.Ok));
        Assert.That(Expect.Type<DatagramFrame>(parsed[0]).Data.ToArray(), Is.EqualTo(new byte[] { 1, 2, 3 }));

        // Ohne Length-Feld (0x30): die Daten reichen bis zum Paketende (RFC 9221 §4).
        byte[] noLength = [0x30, 9, 8, 7, 6];
        Assert.That(FrameParser.TryParseAll(noLength, out List<Frame> parsed2), Is.EqualTo(FrameParseResult.Ok));
        Assert.That(Expect.Type<DatagramFrame>(parsed2[0]).Data.ToArray(), Is.EqualTo(new byte[] { 9, 8, 7, 6 }));
    }

    [Test]
    public void Datagrams_AreNotSent_WithoutNegotiation()
    {
        // Server ohne enableDatagrams ⇒ weder TP noch Setting ⇒ Senden verweigert (RFC 9221 §3 /
        // RFC 9297 §2.1.1 MUST NOT).
        (Http3ClientConnection client, Http3ServerConnection server, _, ServerCertificate cert) =
            DatagramPair(serverDatagrams: false);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        Assert.That(client.DatagramsNegotiated, Is.False);
        Assert.That(client.Quic.PeerMaxDatagramFrameSize, Is.EqualTo(0UL));
        (Http3Tunnel tunnel, ulong _) = OpenTunnel(client, server);
        Assert.That(tunnel.TrySendDatagram([1, 2, 3]), Is.False);
    }

    [Test]
    public void HttpDatagrams_EchoOverConnectTunnel_EndToEnd()
    {
        (Http3ClientConnection client, Http3ServerConnection server, Func<Http3Tunnel?> serverTunnel, ServerCertificate cert) =
            DatagramPair(serverDatagrams: true);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        Assert.That(client.DatagramsNegotiated, Is.True);
        Assert.That(server.DatagramsNegotiated, Is.True);
        Assert.That(client.Quic.PeerMaxDatagramFrameSize, Is.EqualTo(65535UL)); // RFC 9221 §3 RECOMMENDED

        (Http3Tunnel tunnel, ulong _) = OpenTunnel(client, server);

        // Client → Server.
        Assert.That(tunnel.TrySendDatagram([10, 20, 30]), Is.True);
        byte[]? received = null;
        for (int round = 0; round < 10 && received is null; round++)
        {
            Pump(client, server);
            serverTunnel()!.TryReceiveDatagram(out received);
        }
        Assert.That(received, Is.EqualTo(new byte[] { 10, 20, 30 }));

        // Server → Client (Echo).
        Assert.That(serverTunnel()!.TrySendDatagram([30, 20, 10]), Is.True);
        byte[]? echo = null;
        for (int round = 0; round < 10 && echo is null; round++)
        {
            Pump(client, server);
            tunnel.TryReceiveDatagram(out echo);
        }
        Assert.That(echo, Is.EqualTo(new byte[] { 30, 20, 10 }));
        Assert.That(client.IsClosing, Is.False);
        Assert.That(server.IsClosing, Is.False);
    }

    [Test]
    public void Datagram_ForRequestWithoutDatagramSemantics_AbortsTheRequestStream()
    {
        // RFC 9297 §2: GET definiert keine Datagram-Semantik ⇒ der Server MUSS den Request beenden
        // (STREAM-Fehler H3_DATAGRAM_ERROR 0x33) — die Verbindung lebt weiter. Der Request darf dafür
        // noch nicht beantwortet sein ⇒ Roh-Client sendet ein GET OHNE FIN (Server wartet auf den Rest).
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        using var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] },
                                                     enableDatagrams: true);
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new Quic.Connection.QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            PumpRaw(client, server);

        QuicStream control = client.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
        QuicStream request = client.OpenBidirectionalStream();
        request.Write(Http3Frames.Build(Http3FrameType.Headers, QpackEncoder.Encode(
        [
            new HeaderField(":method", "GET"),
            new HeaderField(":scheme", "https"),
            new HeaderField(":authority", "localhost"),
            new HeaderField(":path", "/haengt"),
        ]))); // KEIN Finish ⇒ der Server wartet und hat den Request unbeantwortet offen
        for (int round = 0; round < 5; round++)
            PumpRaw(client, server);

        Assert.That(client.TrySendDatagram([0x00, 0x01]), Is.True); // Quarter 0 ⇒ Stream 0 (der offene GET)
        for (int round = 0; round < 10 && !request.IsResetByPeer; round++)
            PumpRaw(client, server);

        Assert.That(request.IsResetByPeer, Is.True, "Der Server muss den Request-Stream abbrechen.");
        Assert.That(request.PeerResetErrorCode, Is.EqualTo(Http3Error.DatagramError));
        Assert.That(server.IsClosing, Is.False, "Stream-Fehler, KEIN Verbindungsfehler (§2).");
    }

    private static void PumpRaw(Quic.Connection.QuicClientConnection client, Http3ServerConnection server)
    {
        client.CheckLossDetectionTimeout();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    [Test]
    public void MalformedHttpDatagram_IsConnectionError()
    {
        // Leeres QUIC-DATAGRAM ⇒ Quarter Stream ID nicht parsbar ⇒ H3_DATAGRAM_ERROR (RFC 9297 §2.1).
        (Http3ClientConnection client, Http3ServerConnection server, _, ServerCertificate cert) =
            DatagramPair(serverDatagrams: true);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        Assert.That(client.Quic.TrySendDatagram([]), Is.True); // roh, unter der HTTP-Schicht vorbei
        for (int round = 0; round < 10 && !server.IsClosing; round++)
            Pump(client, server);
        Pump(client, server);

        Assert.That(server.IsClosing, Is.True);
        Assert.That(client.PeerCloseFrame, Is.Not.Null);
        Assert.That(client.PeerCloseFrame!.ErrorCode, Is.EqualTo(Http3Error.DatagramError));
    }

    [Test]
    public void Datagram_ForUnknownStream_IsSilentlyDropped()
    {
        (Http3ClientConnection client, Http3ServerConnection server, _, ServerCertificate cert) =
            DatagramPair(serverDatagrams: true);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        Assert.That(client.Quic.TrySendDatagram([0x2a, 0xff]), Is.True); // Quarter 42 ⇒ Stream 168: nie geöffnet
        for (int round = 0; round < 10; round++)
            Pump(client, server);
        Assert.That(server.IsClosing, Is.False, "Unbekannter Stream ⇒ still verwerfen (§2.1 SHALL).");
    }

    [Test]
    public void H3DatagramSetting_WithInvalidValue_IsSettingsError()
    {
        // SETTINGS_H3_DATAGRAM MUSS 0 oder 1 sein (RFC 9297 §2.1.1) — Wert 2 ⇒ H3_SETTINGS_ERROR.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        using var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] });
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new Quic.Connection.QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }

        QuicStream control = client.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        var writer = new Quic.Core.Buffers.BufferWriter(8);
        try
        {
            writer.WriteVarInt(Http3Setting.H3Datagram);
            writer.WriteVarInt(2);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, writer.WrittenSpan.ToArray()));
        }
        finally { writer.Dispose(); }

        for (int round = 0; round < 10 && !server.IsClosing; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }
        Assert.That(server.IsClosing, Is.True);
        Assert.That(client.PeerCloseFrame!.ErrorCode, Is.EqualTo(Http3Error.SettingsError));
    }



    // ---- Helfer ---------------------------------------------------------------------------

    /// <summary>
    /// Client (Datagramme an) + Server (Datagramme je nach <paramref name="serverDatagrams"/>) mit
    /// „datagram-echo"-connectHandler; Handshake + SETTINGS gepumpt.
    /// </summary>
    private static (Http3ClientConnection, Http3ServerConnection, Func<Http3Tunnel?>, ServerCertificate)
        DatagramPair(bool serverDatagrams)
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        Http3Tunnel? serverTunnel = null;

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] },
            connectHandler: request => request.Protocol == "datagram-echo"
                ? new Http3ConnectResult { Status = 200, OnTunnel = t => serverTunnel = t }
                : new Http3ConnectResult { Status = 501 },
            enableDatagrams: serverDatagrams);
        var client = new Http3ClientConnection("localhost", certificateValidation: validation,
                                               enableDatagrams: true);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();
        for (int round = 0; round < 5; round++)
            Pump(client, server); // SETTINGS beidseitig eintreffen lassen

        return (client, server, () => serverTunnel, cert);
    }

    private static (Http3Tunnel, ulong) OpenTunnel(Http3ClientConnection client, Http3ServerConnection server)
    {
        ulong streamId = client.SendExtendedConnect("localhost", "/", "datagram-echo");
        Http3Tunnel? tunnel = null;
        for (int round = 0; round < 20 && tunnel is null; round++)
        {
            Pump(client, server);
            client.TryGetConnectResponse(streamId, out _, out _, out tunnel);
        }
        Assert.That(tunnel, Is.Not.Null);
        return (tunnel!, streamId);
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
