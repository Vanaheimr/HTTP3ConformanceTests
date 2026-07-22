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
/// Malformed-Erkennung (RFC 9114 §4.1.2, §4.2, §4.3): malformed Requests beantwortet der Server mit
/// 400 (MAY) und bricht das Lesen mit dem Stream-Fehler H3_MESSAGE_ERROR ab, OHNE den Handler
/// aufzurufen; malformed Responses DARF der Client nicht akzeptieren. Die Verbindung lebt jeweils weiter.
/// </summary>
[TestFixture]
public class Http3MalformedTests
{
    // ---- Validator-Units (Grenzfälle) -----------------------------------------------------

    [Test]
    public void Validator_CatchesPseudoHeaderViolations()
    {
        // Großbuchstabe im Feldnamen (§4.2 MUST).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "h"), new(":path", "/"), new("X-Bad", "1")]), Is.Not.Null);
        // Pseudo-Header nach regulärem Feld (§4.3).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":method", "GET"), new("accept", "*/*"), new(":scheme", "https"), new(":path", "/"), new(":authority", "h")]), Is.Not.Null);
        // Antwort-Pseudo-Header im Request (§4.3).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":status", "200"), new(":method", "GET"), new(":scheme", "https"), new(":authority", "h"), new(":path", "/")]), Is.Not.Null);
        // userinfo in :authority (§4.3.1).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "user@host"), new(":path", "/")]), Is.Not.Null);
        // :authority und Host widersprechen sich (§4.3.1).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "a"), new(":path", "/"), new("host", "b")]), Is.Not.Null);
        // CR/LF im Feldwert (Request-Smuggling-Schutz).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "h"), new(":path", "/"), new("x", "a\r\nb")]), Is.Not.Null);
        // Wohlgeformt (mit Host statt :authority).
        Assert.That(Http3MessageValidator.ValidateRequestHeaders(
            [new(":method", "GET"), new(":scheme", "https"), new(":path", "/"), new("host", "h")]), Is.Null);

        // Antworten: :status fehlt / doppelt / nicht numerisch (§4.3.2).
        Assert.That(Http3MessageValidator.ValidateResponseHeaders([new("content-type", "text/plain")], out _), Is.Not.Null);
        Assert.That(Http3MessageValidator.ValidateResponseHeaders([new(":status", "200"), new(":status", "204")], out _), Is.Not.Null);
        Assert.That(Http3MessageValidator.ValidateResponseHeaders([new(":status", "abc")], out _), Is.Not.Null);
        Assert.That(Http3MessageValidator.ValidateResponseHeaders([new(":status", "204")], out int ok), Is.Null);
        Assert.That(ok, Is.EqualTo(204));

        // Widersprüchliche content-length-Werte (§4.1.2).
        Assert.That(Http3MessageValidator.ValidateContentLength(
            [new("content-length", "5"), new("content-length", "6")], 5, contentNeverPresent: false), Is.Not.Null);
    }

    [Test]
    public void Client_RefusesToSend_MalformedOwnRequest()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] });
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        client.InitializeHttp3();

        // Großbuchstaben-Header ⇒ MUST NOT generate (§4.2) ⇒ lokal abgelehnt.
        Assert.Throws<ArgumentException>(() => client.SendRequest(
            Http3Request.Get("localhost", "/") with { AdditionalHeaders = [new HeaderField("X-Bad", "1")] }));
        // Verbindungsspezifisches Feld ⇒ ebenso.
        Assert.Throws<ArgumentException>(() => client.SendRequest(
            Http3Request.Get("localhost", "/") with { AdditionalHeaders = [new HeaderField("connection", "keep-alive")] }));
        // Pseudo-Header im Trailer ⇒ ebenso (§4.3).
        Assert.Throws<ArgumentException>(() => client.SendRequest(
            Http3Request.Get("localhost", "/") with { Trailers = [new HeaderField(":method", "GET")] }));
    }

    // ---- Malformed Requests ⇒ Server: 400 + H3_MESSAGE_ERROR, kein Handler ----------------

    [Test]
    public void UppercaseFieldName_IsRejectedWith400()
        => AssertRejected400(stream => WriteHeaders(stream,
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/"), new("X-Bad", "1")]));

    [Test]
    public void PseudoHeaderAfterRegularField_IsRejectedWith400()
        => AssertRejected400(stream => WriteHeaders(stream,
            [new(":method", "GET"), new("accept", "*/*"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/")]));

    [Test]
    public void MissingPathPseudoHeader_IsRejectedWith400()
        => AssertRejected400(stream => WriteHeaders(stream,
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "localhost")]));

    [Test]
    public void ConnectionSpecificField_IsRejectedWith400()
        => AssertRejected400(stream => WriteHeaders(stream,
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/"), new("connection", "keep-alive")]));

    [Test]
    public void TeOtherThanTrailers_IsRejectedWith400()
        => AssertRejected400(stream => WriteHeaders(stream,
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/"), new("te", "gzip")]));

    [Test]
    public void ContentLengthMismatch_IsRejectedWith400()
        => AssertRejected400(stream =>
        {
            WriteHeaders(stream,
                [new(":method", "POST"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/"), new("content-length", "10")]);
            stream.Write(Http3Frames.Build(Http3FrameType.Data, [1, 2, 3])); // 3 ≠ 10 (§4.1.2)
        });

    [Test]
    public void PseudoHeaderInTrailers_IsRejectedWith400()
        => AssertRejected400(stream =>
        {
            WriteHeaders(stream,
                [new(":method", "POST"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/")]);
            stream.Write(Http3Frames.Build(Http3FrameType.Data, [1]));
            WriteHeaders(stream, [new(":status", "200")]); // Pseudo-Header im Trailer (§4.3)
        });

    [Test]
    public void TeTrailers_IsAccepted_RequestSucceeds()
    {
        (int status, ulong? stopCode, int handled) = RunRawRequest(stream => WriteHeaders(stream,
            [new(":method", "GET"), new(":scheme", "https"), new(":authority", "localhost"), new(":path", "/"), new("te", "trailers")]));
        Assert.That(status, Is.EqualTo(200));
        Assert.That(handled, Is.EqualTo(1));
        Assert.That(stopCode, Is.Null);
    }

    [Test]
    public void Connect_IsWellFormed_ButAnsweredWith501()
    {
        // §4.4: gültiger CONNECT (nur :method + :authority) — dieser Server unterstützt ihn nicht.
        (int status, ulong? _, int handled) = RunRawRequest(stream => WriteHeaders(stream,
            [new(":method", "CONNECT"), new(":authority", "localhost:443")]));
        Assert.That(status, Is.EqualTo(501));
        Assert.That(handled, Is.EqualTo(0));
    }

    // ---- Malformed Responses ⇒ Client: verwerfen (MUST NOT accept), Verbindung lebt -------

    [Test]
    public void ResponseWithoutStatus_IsDiscardedAsMalformed()
        => AssertResponseMalformed(section: [new("content-type", "text/plain")]);

    [Test]
    public void ResponseWithUppercaseFieldName_IsDiscardedAsMalformed()
        => AssertResponseMalformed(section: [new(":status", "200"), new("X-Bad", "1")]);

    [Test]
    public void ResponseContentLengthMismatch_IsDiscardedAsMalformed()
    {
        (Http3ClientConnection client, QuicServerConnection server, ulong streamId, ServerCertificate cert) = StartRawServerExchange();
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using QuicServerConnection s = server;

        QuicStream stream = server.Streams[streamId];
        stream.Write(Http3Frames.Build(Http3FrameType.Headers,
            QpackEncoder.Encode([new(":status", "200"), new("content-length", "10")])));
        stream.Write(Http3Frames.Build(Http3FrameType.Data, [1, 2, 3])); // 3 ≠ 10
        stream.Finish();

        for (int round = 0; round < 10 && !client.IsResponseMalformed(streamId); round++)
            Pump2(client, server);
        Assert.That(client.IsResponseMalformed(streamId), Is.True);
        Assert.That(client.TryGetResponse(streamId, out _), Is.False);
        Assert.That(client.IsClosing, Is.False);
    }

    [Test]
    public void NoContent204_WithContentLength_IsAccepted()
    {
        // §4.1.2: rumpflos definierte Antworten (204) dürfen einen content-length tragen,
        // obwohl kein Content in DATA-Frames folgt.
        (Http3ClientConnection client, QuicServerConnection server, ulong streamId, ServerCertificate cert) = StartRawServerExchange();
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using QuicServerConnection s = server;

        QuicStream stream = server.Streams[streamId];
        stream.Write(Http3Frames.Build(Http3FrameType.Headers,
            QpackEncoder.Encode([new(":status", "204"), new("content-length", "5")])));
        stream.Finish();

        Http3Response? response = null;
        for (int round = 0; round < 10 && response is null; round++)
        {
            Pump2(client, server);
            client.TryGetResponse(streamId, out response);
        }
        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(204));
        Assert.That(response.Body, Is.Empty);
    }

    // ---- Helfer ---------------------------------------------------------------------------

    private static void WriteHeaders(QuicStream stream, HeaderField[] fields)
        => stream.Write(Http3Frames.Build(Http3FrameType.Headers, EncodeSectionRaw(fields)));

    /// <summary>
    /// Kodiert eine Field Section ausschließlich als „Literal Field Line with Literal Name" und lässt
    /// die Namen UNVERÄNDERT — anders als <see cref="QpackEncoder"/>, der Namen konventionsgemäß
    /// kleinschreibt. Nur so lassen sich Großbuchstaben-Verstöße (§4.2) auf der Leitung nachstellen.
    /// </summary>
    private static byte[] EncodeSectionRaw(HeaderField[] fields)
    {
        var writer = new org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers.BufferWriter(128);
        try
        {
            writer.WriteByte(0x00); // Field Section Prefix: Required Insert Count = 0, Base = 0
            writer.WriteByte(0x00);
            foreach (HeaderField field in fields)
            {
                QpackPrimitives.EncodeString(ref writer, field.Name, 3, 0b0010_0000);
                QpackPrimitives.EncodeString(ref writer, field.Value, 7, 0x00);
            }
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
    }

    /// <summary>
    /// Roh-Client sendet einen (bösen) Request; erwartet: 400, kein Handler-Aufruf, Leseabbruch des
    /// Servers mit H3_MESSAGE_ERROR (§4.1.2), Verbindung bleibt offen.
    /// </summary>
    private static void AssertRejected400(Action<QuicStream> writeRequest)
    {
        (int status, ulong? stopCode, int handled) = RunRawRequest(writeRequest);
        Assert.That(status, Is.EqualTo(400));
        Assert.That(handled, Is.EqualTo(0));
        Assert.That(stopCode, Is.EqualTo(Http3Error.MessageError));
    }

    /// <summary>
    /// Fährt Handshake + Control-Stream hoch, sendet den Request per <paramref name="writeRequest"/>
    /// (FIN wird ergänzt) und liefert (Status der Antwort, STOP_SENDING-Code, Handler-Aufrufe).
    /// </summary>
    private static (int Status, ulong? StopCode, int Handled) RunRawRequest(Action<QuicStream> writeRequest)
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        int handled = 0;
        using var server = new Http3ServerConnection(cert, _ => { handled++; return new Http3Response { Status = 200, Body = [] }; });
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
        writeRequest(request);
        request.Finish();

        var received = new List<byte>();
        for (int round = 0; round < 15; round++)
        {
            Pump(client, server);
            received.AddRange(request.Read());
        }
        Assert.That(server.IsClosing, Is.False, "Malformed ist ein Stream-, kein Verbindungsfehler.");

        Assert.That(Http3Frames.TryReadAll(received.ToArray(), out List<Http3Frame> frames, out _), Is.True);
        Http3Frame headersFrame = frames.First(f => f.Type == Http3FrameType.Headers);
        Assert.That(QpackDecoder.Decode(headersFrame.Payload.Span, out List<HeaderField> headers), Is.EqualTo(QpackResult.Ok));
        int status = int.Parse(headers.First(h => h.Name == ":status").Value);
        return (status, request.PeerStopSendingErrorCode, handled);
    }

    /// <summary>
    /// Roh-Server sendet die angegebene Antwort-Sektion (+ FIN); erwartet: der Client verwirft die
    /// Antwort als malformed, die Verbindung bleibt offen.
    /// </summary>
    private static void AssertResponseMalformed(HeaderField[] section)
    {
        (Http3ClientConnection client, QuicServerConnection server, ulong streamId, ServerCertificate cert) = StartRawServerExchange();
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using QuicServerConnection s = server;

        QuicStream stream = server.Streams[streamId];
        stream.Write(Http3Frames.Build(Http3FrameType.Headers, EncodeSectionRaw(section)));
        stream.Finish();

        for (int round = 0; round < 10 && !client.IsResponseMalformed(streamId); round++)
            Pump2(client, server);
        Assert.That(client.IsResponseMalformed(streamId), Is.True, "Die malformed Antwort muss verworfen werden.");
        Assert.That(client.TryGetResponse(streamId, out _), Is.False);
        Assert.That(client.IsClosing, Is.False);
    }

    private static (Http3ClientConnection, QuicServerConnection, ulong, ServerCertificate) StartRawServerExchange()
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        var server = new QuicServerConnection(cert);
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
        return (client, server, streamId, cert);
    }

    private static void Pump(QuicClientConnection client, Http3ServerConnection server)
    {
        client.CheckLossDetectionTimeout();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }

    private static void Pump(Http3ClientConnection client, Http3ServerConnection server)
    {
        client.CheckTimeouts();
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
