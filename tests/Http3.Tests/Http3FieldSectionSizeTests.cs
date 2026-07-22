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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2): Größe einer Field Section = Σ (Name + Wert +
/// 32 Bytes) je Feld, unkomprimiert. Wer das Setting empfangen hat, SOLL keine größeren Sektionen
/// senden; ein Server MAG zu große Request-Header mit 431 beantworten, ein Client zu große
/// Antworten verwerfen.
/// </summary>
[TestFixture]
public class Http3FieldSectionSizeTests
{
    [Test]
    public void FieldSectionSize_UsesUncompressedSizePlus32PerField()
    {
        // "ab" (2) + "cde" (3) + 32 = 37; ":x" (2) + "" (0) + 32 = 34 ⇒ 71.
        Assert.That(Http3Qpack.FieldSectionSize(
        [
            new HeaderField("ab", "cde"),
            new HeaderField(":x", ""),
        ]), Is.EqualTo(71UL));
    }

    [Test]
    public void Client_RefusesRequest_ExceedingServersAnnouncedLimit()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        Http3Response Handler(Http3Request request) => new() { Status = 200, Body = [] };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler, maxFieldSectionSize: 200);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();
        for (int round = 0; round < 5; round++)
            Pump(client, server); // die SETTINGS des Servers (Limit 200) eintreffen lassen

        // Zu große Header ⇒ SHOULD NOT senden ⇒ der Client verweigert lokal (§4.2.2).
        var huge = Http3Request.Get("localhost", "/") with
        {
            AdditionalHeaders = [new HeaderField("x-big", new string('a', 500))],
        };
        Assert.Throws<ArgumentException>(() => client.SendRequest(huge));

        // Ein normaler GET (Sektion < 200 Bytes) läuft weiterhin durch.
        ulong ok = client.SendRequest(Http3Request.Get("localhost", "/"));
        Http3Response? response = null;
        for (int round = 0; round < 30 && response is null; round++)
        {
            Pump(client, server);
            client.TryGetResponse(ok, out response);
        }
        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));
    }

    [Test]
    public void Server_Responds431_ToOversizedRequestHeaders_WithoutInvokingHandler()
    {
        // Ein Roh-QUIC-Client umgeht die Sender-Prüfung und schickt zu große Header —
        // der Server antwortet 431 (RFC 6585), ruft den Handler NICHT auf und bittet per
        // STOP_SENDING (H3_NO_ERROR, §4.1) um das Ende des Requests.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        int handled = 0;
        using var server = new Http3ServerConnection(cert, request => { handled++; return new Http3Response { Status = 200, Body = [] }; },
                                                     maxFieldSectionSize: 200);
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);

        QuicStream control = client.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));

        QuicStream request = client.OpenBidirectionalStream();
        request.Write(Http3Frames.Build(Http3FrameType.Headers, QpackEncoder.Encode(
        [
            new HeaderField(":method", "GET"),
            new HeaderField(":scheme", "https"),
            new HeaderField(":authority", "localhost"),
            new HeaderField(":path", "/"),
            new HeaderField("x-big", new string('a', 500)),
        ])));
        request.Finish();

        var received = new List<byte>();
        for (int round = 0; round < 15; round++)
        {
            Pump(client, server);
            received.AddRange(request.Read());
        }

        Assert.That(handled, Is.EqualTo(0)); // der Handler sah den Request nie
        Assert.That(Http3Frames.TryReadAll(received.ToArray(), out List<Http3Frame> frames, out _), Is.True);
        Http3Frame headersFrame = frames.First(f => f.Type == Http3FrameType.Headers);
        Assert.That(QpackDecoder.Decode(headersFrame.Payload.Span, out List<HeaderField> headers), Is.EqualTo(QpackResult.Ok));
        Assert.That(headers.First(h => h.Name == ":status").Value, Is.EqualTo("431"));
        Assert.That(request.PeerStopSendingErrorCode, Is.EqualTo(Http3Error.NoError)); // §4.1: H3_NO_ERROR
        Assert.That(server.IsClosing, Is.False, "431 ist eine normale Antwort, kein Verbindungsfehler.");
    }

    [Test]
    public void Server_Downgrades_OversizedResponseHeaders_To500()
    {
        // Unser eigener Server respektiert das Client-Limit (SHOULD NOT senden): statt der zu
        // großen Antwort-Header schickt er ein minimales 500.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        Http3Response Handler(Http3Request request) => new()
        {
            Status = 200,
            Headers = [new HeaderField("x-big", new string('a', 500))],
            Body = System.Text.Encoding.UTF8.GetBytes("Rumpf"),
        };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation,
                                                     maxFieldSectionSize: 200);
        client.Start();

        ulong requestStream = 0;
        bool requestSent = false;
        Http3Response? response = null;
        for (int round = 0; round < 40 && response is null; round++)
        {
            Pump(client, server);
            if (client.HandshakeConfirmed && !requestSent)
            {
                client.InitializeHttp3();
                for (int extra = 0; extra < 3; extra++)
                    Pump(client, server); // dem Server unsere SETTINGS (Limit 200) zustellen
                requestStream = client.SendRequest(Http3Request.Get("localhost", "/"));
                requestSent = true;
            }
            if (requestSent)
                client.TryGetResponse(requestStream, out response);
        }

        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(500));       // heruntergestuft statt Limit-Verstoß
        Assert.That(response.GetHeader("x-big"), Is.Null);
        Assert.That(client.IsResponseTooLarge(requestStream), Is.False);
    }

    [Test]
    public void Client_DiscardsOversizedResponse_FromRawServer()
    {
        // Ein Roh-Server ignoriert unser Limit und sendet zu große Antwort-Header — der Client
        // verwirft die Antwort (§4.2.2 „can discard") und bricht den Stream ab; die Verbindung lebt.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation,
                                                     maxFieldSectionSize: 200);
        using var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump2(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        QuicStream control = server.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));

        ulong streamId = client.SendRequest(Http3Request.Get("localhost", "/"));
        for (int round = 0; round < 5; round++)
            Pump2(client, server);

        server.Streams[streamId].Write(Http3Frames.Build(Http3FrameType.Headers, QpackEncoder.Encode(
        [
            new HeaderField(":status", "200"),
            new HeaderField("x-big", new string('a', 500)),
        ])));
        for (int round = 0; round < 10 && !client.IsResponseTooLarge(streamId); round++)
            Pump2(client, server);

        Assert.That(client.IsResponseTooLarge(streamId), Is.True, "Die zu große Antwort muss verworfen werden.");
        Assert.That(client.TryGetResponse(streamId, out _), Is.False);
        Assert.That(client.IsClosing, Is.False, "Verwerfen ist ein Stream-, kein Verbindungsvorgang.");
        for (int round = 0; round < 10 && !server.Streams[streamId].IsResetByPeer; round++)
            Pump2(client, server);
        Assert.That(server.Streams[streamId].IsResetByPeer, Is.True);
        Assert.That(server.Streams[streamId].PeerResetErrorCode, Is.EqualTo(Http3Error.RequestCancelled));
    }

    // ---- Helfer ---------------------------------------------------------------------------

    private static void Pump(Http3ClientConnection client, Http3ServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    private static void Pump(QuicClientConnection client, Http3ServerConnection server)
    {
        client.CheckLossDetectionTimeout();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    private static void Pump2(Http3ClientConnection client, QuicServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
