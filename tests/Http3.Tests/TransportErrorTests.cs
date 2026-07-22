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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Tests der Transport-Error-Matrix (RFC 9000 §11/§20.1): Protokollverstöße der Gegenseite müssen mit dem
/// passenden Fehlercode via CONNECTION_CLOSE beantwortet werden. Plus Frame-Parser-Fehler und die neuen
/// PATH_CHALLENGE/PATH_RESPONSE-Frames.
/// </summary>
[TestFixture]
public class TransportErrorTests
{
    [Test]
    public void FrameParser_UnknownFrameType_IsAnError()
    {
        Assert.That(FrameParser.TryParseAll([0x1f], out _), Is.EqualTo(FrameParseResult.UnknownFrameType));
    }

    [Test]
    public void FrameParser_TruncatedFrame_IsAnEncodingError()
    {
        // CRYPTO-Frame-Typ (0x06) ohne Offset/Länge/Daten ⇒ unvollständig.
        Assert.That(FrameParser.TryParseAll([0x06], out _), Is.EqualTo(FrameParseResult.EncodingError));
    }

    [Test]
    public void PathChallengeAndResponse_RoundTrip()
    {
        byte[] bytes = FrameParser.Serialize([new PathChallengeFrame(0x0123456789abcdef), new PathResponseFrame(0x00ff00ff00ff00ff)]);
        Assert.That(FrameParser.TryParseAll(bytes, out List<Frame> parsed), Is.EqualTo(FrameParseResult.Ok));
        Assert.That(Expect.Type<PathChallengeFrame>(parsed[0]).Data, Is.EqualTo(0x0123456789abcdefUL));
        Assert.That(Expect.Type<PathResponseFrame>(parsed[1]).Data, Is.EqualTo(0x00ff00ff00ff00ffUL));
    }

    [Test]
    public void StreamReceiveBuffer_DataBeyondFlowControlWindow_IsFlowControlError()
    {
        var buffer = new StreamReceiveBuffer { MaxData = 4 };
        Assert.That(buffer.Receive(0, new byte[5], fin: false), Is.EqualTo(StreamReceiveResult.FlowControlError));
    }

    [Test]
    public void StreamReceiveBuffer_InconsistentFinalSize_IsFinalSizeError()
    {
        var buffer = new StreamReceiveBuffer();
        Assert.That(buffer.Receive(0, new byte[4], fin: true), Is.EqualTo(StreamReceiveResult.Ok));       // Final Size = 4
        Assert.That(buffer.Receive(4, new byte[2], fin: false), Is.EqualTo(StreamReceiveResult.FinalSizeError)); // darüber hinaus
    }

    // ---- Integration: STREAM_LIMIT_ERROR end-to-end --------------------------------------

    [Test]
    public void PeerExceedingStreamLimit_IsClosedWithStreamLimitError()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };

        // Server erlaubt dem Client nur EINEN bidirektionalen Stream (Index 0).
        var serverParams = new TransportParameters { InitialMaxStreamsBidiValue = 1 };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert, serverParams);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);

        // Der Client eröffnet ZWEI Streams (0 und 1) und sendet auf beiden – Stream 1 verletzt das Limit.
        client.OpenBidirectionalStream().Write([1]);
        QuicStream second = client.OpenBidirectionalStream();
        second.Write([2]);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.That(server.IsClosing, Is.True, "Der Server muss die Verbindung wegen Stream-Limit-Verstoßes schließen.");
        // Der Client empfängt das CONNECTION_CLOSE mit dem korrekten Fehlercode.
        Assert.That(client.PeerCloseFrame, Is.Not.Null);
        Assert.That(client.PeerCloseFrame!.ErrorCode, Is.EqualTo((ulong)TransportError.StreamLimitError));
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
