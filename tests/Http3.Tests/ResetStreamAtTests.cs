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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset): das RESET_STREAM mit garantierter
/// Teilzustellung bis zu einer Reliable Size, plus der zugehörige reset_stream_at-Transportparameter.
/// </summary>
[TestFixture]
public class ResetStreamAtTests
{
    // ---- Unit: Frame-Kodierung ------------------------------------------------------------

    [Test]
    public void ResetStreamAtFrame_RoundTrips()
    {
        var original = new ResetStreamAtFrame(StreamId: 8, ApplicationErrorCode: 0x0c, FinalSize: 1000, ReliableSize: 40);
        byte[] bytes = FrameParser.Serialize([original]);

        Assert.That(FrameParser.TryParseAll(bytes, out var frames), Is.EqualTo(FrameParseResult.Ok));
        var frame = Expect.Type<ResetStreamAtFrame>(Expect.Single(frames));
        Assert.That(frame.StreamId, Is.EqualTo(8UL));
        Assert.That(frame.ApplicationErrorCode, Is.EqualTo(0x0cUL));
        Assert.That(frame.FinalSize, Is.EqualTo(1000UL));
        Assert.That(frame.ReliableSize, Is.EqualTo(40UL));
    }

    [Test]
    public void ResetStreamAtFrame_TruncatedBody_IsEncodingError()
    {
        // Typ 0x24 gefolgt von nur drei der vier Pflicht-VarInts ⇒ FRAME_ENCODING_ERROR.
        var writer = new BufferWriter();
        try
        {
            writer.WriteVarInt(FrameType.ResetStreamAt);
            writer.WriteVarInt(8);
            writer.WriteVarInt(0x0c);
            writer.WriteVarInt(1000);
            Assert.That(FrameParser.TryParseAll(writer.WrittenSpan.ToArray(), out _), Is.EqualTo(FrameParseResult.EncodingError));
        }
        finally { writer.Dispose(); }
    }

    // ---- Unit: Transportparameter ---------------------------------------------------------

    [Test]
    public void TransportParameter_ResetStreamAt_IsAdvertisedAndParsed()
    {
        var tp = new TransportParameters();
        Assert.That(tp.ResetStreamAtSupported, Is.True); // Standard: aktiv

        Assert.That(TransportParameters.TryDecode(tp.Encode(), out var decoded), Is.True);
        Assert.That(decoded!.PeerSupportsResetStreamAt, Is.True);

        // Abgeschaltet ⇒ Parameter fehlt ⇒ Peer sieht keine Unterstützung.
        var off = new TransportParameters { ResetStreamAtSupported = false };
        Assert.That(TransportParameters.TryDecode(off.Encode(), out var decodedOff), Is.True);
        Assert.That(decodedOff!.PeerSupportsResetStreamAt, Is.False);
    }

    [Test]
    public void TransportParameter_ResetStreamAt_NonEmptyValue_IsRejected()
    {
        // draft §3: ein nicht-leerer Wert ist ein TRANSPORT_PARAMETER_ERROR ⇒ Decode schlägt fehl.
        var writer = new BufferWriter();
        try
        {
            writer.WriteVarInt(0x1d);          // reset_stream_at
            writer.WriteVarInt(1);             // Länge 1 (unzulässig)
            writer.WriteBytes(new byte[] { 0 });
            Assert.That(TransportParameters.TryDecode(writer.WrittenSpan.ToArray(), out _), Is.False);
        }
        finally { writer.Dispose(); }
    }

    // ---- Unit: Empfangspuffer (zuverlässige Teilzustellung) -------------------------------

    [Test]
    public void ReceiveBuffer_ResetAt_DeliversReliablePrefix_ThenSurfacesReset()
    {
        var recv = new StreamReceiveBuffer { MaxData = 1000 };
        Assert.That(recv.Receive(0, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, fin: false), Is.EqualTo(StreamReceiveResult.Ok));

        // RESET_STREAM_AT: Final Size 100, aber die ersten 4 Bytes bleiben zustellbar.
        Assert.That(recv.ResetAt(0x0c, finalSize: 100, reliableSize: 4), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv.ResetReceived, Is.True);
        Assert.That(recv.ReliableSize, Is.EqualTo(4UL));

        // Nur die zuverlässigen 4 Bytes werden geliefert, der Rest verworfen.
        Assert.That(recv.ReadAvailable(), Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        // §4.5: die volle Final Size zählt als verbrauchter Flow-Control-Kredit.
        Assert.That(recv.BytesConsumed, Is.EqualTo(100UL));
        Assert.That(recv.IsComplete, Is.False);
    }

    [Test]
    public void ReceiveBuffer_ResetAt_ReliableSizeGreaterThanFinalSize_IsFrameEncodingError()
    {
        var recv = new StreamReceiveBuffer { MaxData = 1000 };
        Assert.That(recv.ResetAt(0x0c, finalSize: 10, reliableSize: 20), Is.EqualTo(StreamReceiveResult.FrameEncodingError));
    }

    [Test]
    public void ReceiveBuffer_ResetAt_LaterFrameMayOnlyLowerReliableSize()
    {
        var recv = new StreamReceiveBuffer { MaxData = 1000 };
        Assert.That(recv.Receive(0, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, fin: false), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv.ResetAt(0x0c, finalSize: 100, reliableSize: 6), Is.EqualTo(StreamReceiveResult.Ok));

        // §5.2: eine Erhöhung (Reordering) wird ignoriert …
        Assert.That(recv.ResetAt(0x0c, finalSize: 100, reliableSize: 8), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv.ReliableSize, Is.EqualTo(6UL));

        // … eine Senkung wird übernommen und kürzt bereits Gepuffertes.
        Assert.That(recv.ResetAt(0x0c, finalSize: 100, reliableSize: 3), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv.ReliableSize, Is.EqualTo(3UL));
        Assert.That(recv.ReadAvailable(), Is.EqualTo(new byte[] { 1, 2, 3 }));
    }

    [Test]
    public void ReceiveBuffer_ResetAt_ChangedErrorCode_IsStreamStateError()
    {
        var recv = new StreamReceiveBuffer { MaxData = 1000 };
        Assert.That(recv.ResetAt(0x0c, finalSize: 100, reliableSize: 4), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv.ResetAt(0x0d, finalSize: 100, reliableSize: 4), Is.EqualTo(StreamReceiveResult.StreamStateError));
    }

    [Test]
    public void ReceiveBuffer_ResetAt_LateStreamFrameBeyondReliableSize_IsDropped()
    {
        var recv = new StreamReceiveBuffer { MaxData = 1000 };
        Assert.That(recv.ResetAt(0x0c, finalSize: 100, reliableSize: 4), Is.EqualTo(StreamReceiveResult.Ok));

        // Ein danach eintreffendes STREAM-Frame straddled die Reliable-Grenze: nur bis 4 wird geliefert.
        Assert.That(recv.Receive(0, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, fin: false), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv.ReadAvailable(), Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
    }

    // ---- Unit: Sendepuffer ----------------------------------------------------------------

    [Test]
    public void SendBuffer_ResetAt_EmitsResetStreamAt_WhenPeerSupports()
    {
        var send = new StreamSendBuffer(8) { MaxData = 1000 };
        send.Write(new byte[50]);
        Assert.That(send.NextFrame(50), Is.Not.Null); // 50 Bytes gesendet ⇒ Final Size = 50

        send.ResetAt(0x0c, reliableSize: 20);
        Assert.That(send.IsResetAt, Is.True);
        Assert.That(send.ReliableSize, Is.EqualTo(20UL));

        var atFrame = Expect.Type<ResetStreamAtFrame>(send.TakeResetFrame(peerSupportsResetAt: true));
        Assert.That(atFrame.FinalSize, Is.EqualTo(50UL));
        Assert.That(atFrame.ReliableSize, Is.EqualTo(20UL));
    }

    [Test]
    public void SendBuffer_ResetAt_DegradesToResetStream_WhenPeerLacksSupport()
    {
        var send = new StreamSendBuffer(8) { MaxData = 1000 };
        send.Write(new byte[50]);
        Assert.That(send.NextFrame(50), Is.Not.Null);

        send.ResetAt(0x0c, reliableSize: 20);
        // Ohne Peer-Unterstützung ⇒ gewöhnliches RESET_STREAM (ohne Zustellgarantie).
        var frame = Expect.Type<ResetStreamFrame>(send.TakeResetFrame(peerSupportsResetAt: false));
        Assert.That(frame.FinalSize, Is.EqualTo(50UL));
    }

    [Test]
    public void SendBuffer_ResetAt_ClampsReliableSizeToSentOffset()
    {
        var send = new StreamSendBuffer(8) { MaxData = 1000 };
        send.Write(new byte[10]);
        Assert.That(send.NextFrame(10), Is.Not.Null); // nur 10 Bytes gesendet

        // Es lassen sich nur bereits gesendete Bytes garantieren ⇒ Reliable Size auf 10 begrenzt.
        send.ResetAt(0x0c, reliableSize: 999);
        Assert.That(send.ReliableSize, Is.EqualTo(10UL));
    }

    // ---- Integration (QUIC): Ende-zu-Ende über echte Frame-Verarbeitung -------------------

    [Test]
    public void ResetStreamAt_EndToEnd_PeerReceivesReliablePrefix()
    {
        (QuicClientConnection client, QuicServerConnection server, ServerCertificate cert) = HandshakeInProcess();
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using QuicServerConnection s = server;

        // Der Peer (Server) hat reset_stream_at angekündigt.
        Assert.That(client.PeerTransportParameters!.PeerSupportsResetStreamAt, Is.True);

        // Client sendet 12 Bytes auf einem Bidi-Stream und bricht dann mit Reliable Size 4 ab.
        QuicStream clientStream = client.OpenBidirectionalStream();
        byte[] payload = { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21 };
        clientStream.Write(payload);
        for (int round = 0; round < 5; round++)
            Pump(client, server);

        clientStream.ResetAt(0x0c, reliableSize: 4);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.That(server.IsClosing, Is.False);
        Assert.That(client.IsClosing, Is.False);

        QuicStream serverStream = server.Streams[clientStream.Id.Value];
        Assert.That(serverStream.IsResetByPeer, Is.True);
        Assert.That(serverStream.PeerResetErrorCode, Is.EqualTo(0x0cUL));
        Assert.That(serverStream.PeerReliableSize, Is.EqualTo(4UL));
        // Die zuverlässig zugesagten ersten 4 Bytes sind trotz Reset lesbar.
        Assert.That(serverStream.Read(), Is.EqualTo(new byte[] { 10, 11, 12, 13 }));
    }

    // ---- Helfer ---------------------------------------------------------------------------

    private static (QuicClientConnection, QuicServerConnection, ServerCertificate) HandshakeInProcess()
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var client = new QuicClientConnection("localhost", certificateValidation: validation);
        var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        return (client, server, cert);
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        client.CheckLossDetectionTimeout();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
