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
/// GOAWAY / Graceful Shutdown (RFC 9114 §5.2): der Server kündigt die erste nicht mehr angenommene
/// Request-Stream-ID an, bedient Laufendes zu Ende, weist Späteres mit H3_REQUEST_REJECTED zurück;
/// der Client startet keine neuen Requests mehr und behandelt zurückgewiesene als wiederholbar.
/// </summary>
[TestFixture]
public class Http3GoAwayTests
{
    [Test]
    public void GracefulShutdown_EndToEnd_ClientStopsNewRequests_ServerClosesWithH3NoError()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        Http3Response Handler(Http3Request request) => new()
        {
            Status = 200,
            Body = System.Text.Encoding.UTF8.GetBytes("ok"),
        };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        // Erster Request läuft normal durch.
        ulong first = client.SendRequest(Http3Request.Get("localhost", "/eins"));
        Http3Response? response = null;
        for (int round = 0; round < 30 && response is null; round++)
        {
            Pump(client, server);
            client.TryGetResponse(first, out response);
        }
        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));

        // Server leitet den Graceful Shutdown ein: GOAWAY mit der nächsten Request-Stream-ID (0 + 4).
        server.InitiateGracefulShutdown();
        Assert.That(server.GoAwaySent, Is.EqualTo(4UL));
        for (int round = 0; round < 10 && client.GoAwayStreamId is null; round++)
            Pump(client, server);

        // Der Client kennt die Grenze und MUSS neue Requests verweigern (§5.2).
        Assert.That(client.GoAwayStreamId, Is.EqualTo(4UL));
        Assert.Throws<InvalidOperationException>(() => client.SendRequest(Http3Request.Get("localhost", "/zwei")));

        // Alles bedient ⇒ der Server schließt anständig mit H3_NO_ERROR (Typ 0x1d).
        Assert.That(server.HasPendingRequests, Is.False);
        server.CloseGracefully();
        for (int round = 0; round < 10 && client.PeerCloseFrame is null; round++)
            Pump(client, server);

        Assert.That(client.PeerCloseFrame, Is.Not.Null);
        Assert.That(client.PeerCloseFrame!.IsApplicationError, Is.True);
        Assert.That(client.PeerCloseFrame.ErrorCode, Is.EqualTo(Http3Error.NoError));
        Assert.That(client.IsDraining, Is.True);
    }

    [Test]
    public void LateRequest_AfterGoAway_IsRejectedWithRequestRejected()
    {
        // Ein „ungezogener" Roh-QUIC-Client ignoriert das GOAWAY und schickt trotzdem einen Request —
        // der Server MUSS ihn zurückweisen (H3_REQUEST_REJECTED), ohne den Handler aufzurufen (§5.2).
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        int handled = 0;
        using var server = new Http3ServerConnection(cert, request => { handled++; return new Http3Response { Status = 200, Body = [] }; });
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);

        // Ordentlicher Control-Stream + erster Request (Stream 0) — wird noch bedient.
        QuicStream control = client.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
        QuicStream firstRequest = client.OpenBidirectionalStream();
        firstRequest.Write(Http3Frames.Build(Http3FrameType.Headers, EncodeGetHeaders("/eins")));
        firstRequest.Finish();
        for (int round = 0; round < 10; round++)
            Pump(client, server);
        Assert.That(handled, Is.EqualTo(1));

        server.InitiateGracefulShutdown();
        Assert.That(server.GoAwaySent, Is.EqualTo(4UL));
        for (int round = 0; round < 5; round++)
            Pump(client, server);

        // Der Roh-Client sendet TROTZDEM einen zweiten Request (Stream 4).
        QuicStream lateRequest = client.OpenBidirectionalStream();
        lateRequest.Write(Http3Frames.Build(Http3FrameType.Headers, EncodeGetHeaders("/zwei")));
        lateRequest.Finish();
        for (int round = 0; round < 10 && !lateRequest.IsResetByPeer; round++)
            Pump(client, server);

        Assert.That(handled, Is.EqualTo(1)); // der Handler wurde für den späten Request NICHT aufgerufen
        Assert.That(lateRequest.IsResetByPeer, Is.True, "Der Server muss den späten Request zurücksetzen.");
        Assert.That(lateRequest.PeerResetErrorCode, Is.EqualTo(Http3Error.RequestRejected));
        Assert.That(server.IsClosing, Is.False, "Ein später Request ist KEIN Verbindungsfehler.");
    }

    [Test]
    public void ClientInFlightRequests_AboveGoAwayId_AreMarkedRejected()
    {
        // Roh-QUIC-Server: beantwortet nichts, sendet aber ein GOAWAY mit ID 0 —
        // der bereits laufende Client-Request (Stream 0) gilt damit als NICHT verarbeitet.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        ulong streamId = client.SendRequest(Http3Request.Get("localhost", "/haengt"));
        for (int round = 0; round < 5; round++)
            Pump(client, server);

        QuicStream control = server.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
        control.Write(Http3Frames.Build(Http3FrameType.GoAway, [0x00])); // ID 0: NICHTS wurde verarbeitet
        for (int round = 0; round < 10 && !client.IsRequestRejected(streamId); round++)
            Pump(client, server);

        Assert.That(client.IsRequestRejected(streamId), Is.True, "Der In-Flight-Request muss als zurückgewiesen gelten.");
        Assert.That(client.TryGetResponse(streamId, out _), Is.False);
        // §5.2: der Client räumt den Transportzustand auf (Reset der Sendeseite beim Roh-Server sichtbar).
        for (int round = 0; round < 10 && !server.Streams[streamId].IsResetByPeer; round++)
            Pump(client, server);
        Assert.That(server.Streams[streamId].IsResetByPeer, Is.True);
    }

    [Test]
    public void GoAwayIdentifierIncrease_IsIdError()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        QuicStream control = server.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
        control.Write(Http3Frames.Build(Http3FrameType.GoAway, [0x00]));
        for (int round = 0; round < 5; round++)
            Pump(client, server);
        Assert.That(client.GoAwayStreamId, Is.EqualTo(0UL));

        // §5.2: die GOAWAY-ID darf NIE anwachsen ⇒ H3_ID_ERROR.
        control.Write(Http3Frames.Build(Http3FrameType.GoAway, [0x08]));
        for (int round = 0; round < 10 && !client.IsClosing; round++)
            Pump(client, server);
        Pump(client, server); // das CONNECTION_CLOSE des Clients noch zustellen

        Assert.That(client.IsClosing, Is.True);
        Assert.That(server.PeerCloseFrame, Is.Not.Null);
        Assert.That(server.PeerCloseFrame!.ErrorCode, Is.EqualTo(Http3Error.IdError));
    }

    // ---- Helfer ---------------------------------------------------------------------------

    private static byte[] EncodeGetHeaders(string path)
        => QpackEncoder.Encode(
        [
            new HeaderField(":method", "GET"),
            new HeaderField(":scheme", "https"),
            new HeaderField(":authority", "localhost"),
            new HeaderField(":path", path),
        ]);

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

    private static void Pump(Http3ClientConnection client, QuicServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
