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
public class TransportErrorTests
{
    [Fact]
    public void FrameParser_UnknownFrameType_IsAnError()
    {
        Assert.Equal(FrameParseResult.UnknownFrameType, FrameParser.TryParseAll([0x1f], out _));
    }

    [Fact]
    public void FrameParser_TruncatedFrame_IsAnEncodingError()
    {
        // CRYPTO-Frame-Typ (0x06) ohne Offset/Länge/Daten ⇒ unvollständig.
        Assert.Equal(FrameParseResult.EncodingError, FrameParser.TryParseAll([0x06], out _));
    }

    [Fact]
    public void PathChallengeAndResponse_RoundTrip()
    {
        byte[] bytes = FrameParser.Serialize([new PathChallengeFrame(0x0123456789abcdef), new PathResponseFrame(0x00ff00ff00ff00ff)]);
        Assert.Equal(FrameParseResult.Ok, FrameParser.TryParseAll(bytes, out List<Frame> parsed));
        Assert.Equal(0x0123456789abcdefUL, Assert.IsType<PathChallengeFrame>(parsed[0]).Data);
        Assert.Equal(0x00ff00ff00ff00ffUL, Assert.IsType<PathResponseFrame>(parsed[1]).Data);
    }

    [Fact]
    public void StreamReceiveBuffer_DataBeyondFlowControlWindow_IsFlowControlError()
    {
        var buffer = new StreamReceiveBuffer { MaxData = 4 };
        Assert.Equal(StreamReceiveResult.FlowControlError, buffer.Receive(0, new byte[5], fin: false));
    }

    [Fact]
    public void StreamReceiveBuffer_InconsistentFinalSize_IsFinalSizeError()
    {
        var buffer = new StreamReceiveBuffer();
        Assert.Equal(StreamReceiveResult.Ok, buffer.Receive(0, new byte[4], fin: true));       // Final Size = 4
        Assert.Equal(StreamReceiveResult.FinalSizeError, buffer.Receive(4, new byte[2], fin: false)); // darüber hinaus
    }

    // ---- Integration: STREAM_LIMIT_ERROR end-to-end --------------------------------------

    [Fact]
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
        Assert.True(client.HandshakeConfirmed);

        // Der Client eröffnet ZWEI Streams (0 und 1) und sendet auf beiden – Stream 1 verletzt das Limit.
        client.OpenBidirectionalStream().Write([1]);
        QuicStream second = client.OpenBidirectionalStream();
        second.Write([2]);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.True(server.IsClosing, "Der Server muss die Verbindung wegen Stream-Limit-Verstoßes schließen.");
        // Der Client empfängt das CONNECTION_CLOSE mit dem korrekten Fehlercode.
        Assert.NotNull(client.PeerCloseFrame);
        Assert.Equal((ulong)TransportError.StreamLimitError, client.PeerCloseFrame!.ErrorCode);
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
