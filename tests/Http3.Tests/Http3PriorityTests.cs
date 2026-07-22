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
/// RFC 9218 (Extensible Prioritization Scheme): `priority`-Header (u=0..7, i), PRIORITY_UPDATE-Frame
/// (0xF0700, nur Client-Control-Stream) und das empfohlene Server-Scheduling (§10): aufsteigende
/// Urgency; gleiche Urgency nicht-inkrementell ⇒ Stream-ID-Reihenfolge, inkrementell ⇒ Bandbreite teilen.
/// </summary>
[TestFixture]
public class Http3PriorityTests
{
    // ---- Parser (RFC 9218 §4, Structured Fields) ------------------------------------------

    [Test]
    public void PriorityParse_HandlesDefaultsRangesAndUnknownParameters()
    {
        Assert.That(Http3Priority.Parse(null), Is.EqualTo(new Http3Priority(3, false)));
        Assert.That(Http3Priority.Parse("u=0"), Is.EqualTo(new Http3Priority(0, false)));
        Assert.That(Http3Priority.Parse("u=5, i"), Is.EqualTo(new Http3Priority(5, true)));
        Assert.That(Http3Priority.Parse("i"), Is.EqualTo(new Http3Priority(3, true)));
        Assert.That(Http3Priority.Parse("i=?1"), Is.EqualTo(new Http3Priority(3, true)));
        Assert.That(Http3Priority.Parse("i=?0"), Is.EqualTo(new Http3Priority(3, false)));
        Assert.That(Http3Priority.Parse("u=9"), Is.EqualTo(new Http3Priority(3, false)));        // außerhalb ⇒ ignorieren
        Assert.That(Http3Priority.Parse("u=abc"), Is.EqualTo(new Http3Priority(3, false)));      // typfremd ⇒ ignorieren
        Assert.That(Http3Priority.Parse("u=1, u=6"), Is.EqualTo(new Http3Priority(6, false)));   // letzter gewinnt (SF §3.2)
        Assert.That(Http3Priority.Parse("x=5, u=2, i"), Is.EqualTo(new Http3Priority(2, true))); // unbekannt ⇒ ignorieren
        Assert.That(Http3Priority.Parse("u=1;foo=bar"), Is.EqualTo(new Http3Priority(1, false))); // Member-Parameter ignorieren

        Assert.That(Http3Priority.Default.ToHeaderValue(), Is.EqualTo(""));
        Assert.That(new Http3Priority(0, false).ToHeaderValue(), Is.EqualTo("u=0"));
        Assert.That(new Http3Priority(5, true).ToHeaderValue(), Is.EqualTo("u=5, i"));
        Assert.That(new Http3Priority(3, true).ToHeaderValue(), Is.EqualTo("i"));
    }

    // ---- Scheduling (§10) über den vollen eigenen Stack -----------------------------------

    [Test]
    public void HigherUrgencyResponse_CompletesFirst_DespiteBeingRequestedSecond()
    {
        (int roundA, int roundB) = RunTwoRequests(
            first: Http3Request.Get("localhost", "/big"),                                       // u=3 (Default)
            second: Http3Request.Get("localhost", "/big") with { Priority = new(0, false) });   // u=0

        Assert.That(roundB < roundA, Is.True, $"Die dringlichere Antwort (u=0) muss zuerst fertig sein (B: Runde {roundB}, A: Runde {roundA}).");
    }

    [Test]
    public void SameUrgencyNonIncremental_ServedInStreamIdOrder()
    {
        (int roundA, int roundB) = RunTwoRequests(
            first: Http3Request.Get("localhost", "/big"),
            second: Http3Request.Get("localhost", "/big"));

        Assert.That(roundA < roundB, Is.True, $"Bei gleicher Urgency (nicht inkrementell) gilt Request-Reihenfolge (A: {roundA}, B: {roundB}).");
    }

    [Test]
    public void SameUrgencyIncremental_SharesBandwidth()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        byte[] big = new byte[150_000];
        Http3Response Handler(Http3Request request) => new() { Status = 200, Body = big };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        client.InitializeHttp3();

        var incremental = new Http3Priority(3, true);
        ulong a = client.SendRequest(Http3Request.Get("localhost", "/big") with { Priority = incremental });
        ulong b = client.SendRequest(Http3Request.Get("localhost", "/big") with { Priority = incremental });

        // Beide Antworten müssen VOR ihrer jeweiligen Fertigstellung parallel Fortschritt machen (§10).
        bool sharedProgress = false;
        Http3Response? responseA = null, responseB = null;
        for (int round = 0; round < 2000 && (responseA is null || responseB is null); round++)
        {
            Pump(client, server);
            client.TryGetResponse(a, out responseA);
            client.TryGetResponse(b, out responseB);
            if (responseA is null && responseB is null &&
                server.Quic.Streams[a].Send.SentOffset > 0 && server.Quic.Streams[b].Send.SentOffset > 0)
                sharedProgress = true;
        }

        Assert.That(responseA, Is.Not.Null);
        Assert.That(responseB, Is.Not.Null);
        Assert.That(sharedProgress, Is.True, "Inkrementelle Antworten gleicher Urgency müssen sich die Bandbreite teilen.");
    }

    [Test]
    public void PriorityUpdate_OverridesHeader_Reprioritization()
    {
        // A wird mit u=0 angefragt, dann per PRIORITY_UPDATE auf u=7 (Hintergrund) zurückgestuft —
        // das Update übertrumpft den Header (§7), also gewinnt B (Default u=3).
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        byte[] big = new byte[150_000];
        Http3Response Handler(Http3Request request) => new() { Status = 200, Body = big };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        client.InitializeHttp3();

        ulong a = client.SendRequest(Http3Request.Get("localhost", "/big") with { Priority = new(0, false) });
        ulong b = client.SendRequest(Http3Request.Get("localhost", "/big"));
        client.SendPriorityUpdate(a, new Http3Priority(7, false)); // Prefetch degradieren (§6)

        (int roundA, int roundB) = AwaitBoth(client, server, a, b);
        Assert.That(roundB < roundA, Is.True, $"Das PRIORITY_UPDATE (u=7) muss den Header (u=0) überschreiben (A: {roundA}, B: {roundB}).");
    }

    [Test]
    public void PriorityUpdate_BeforeStreamOpens_IsBufferedAndApplied()
    {
        // Roh-Client: PRIORITY_UPDATE für Stream 4 (u=0) VOR dessen Öffnung — der Server MUSS das
        // letzte Update puffern und beim Öffnen anwenden (§7) ⇒ Stream 4 wird vor Stream 0 bedient.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        byte[] big = new byte[150_000];
        using var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = big });
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);

        QuicStream control = client.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
        control.Write(Http3Frames.Build(Http3FrameType.PriorityUpdateRequest, [0x04, .. "u=0"u8])); // Stream 4

        QuicStream requestA = client.OpenBidirectionalStream(); // Stream 0 (Default u=3)
        requestA.Write(Http3Frames.Build(Http3FrameType.Headers, EncodeGet("/a")));
        requestA.Finish();
        QuicStream requestB = client.OpenBidirectionalStream(); // Stream 4 (per Update u=0)
        requestB.Write(Http3Frames.Build(Http3FrameType.Headers, EncodeGet("/b")));
        requestB.Finish();

        int completeA = -1, completeB = -1;
        for (int round = 0; round < 2000 && (completeA < 0 || completeB < 0); round++)
        {
            Pump(client, server);
            requestA.Read();
            requestB.Read();
            if (completeA < 0 && requestA.IsReceiveComplete) completeA = round;
            if (completeB < 0 && requestB.IsReceiveComplete) completeB = round;
        }

        Assert.That(completeB >= 0 && completeA >= 0, Is.True, "Beide Antworten müssen ankommen.");
        Assert.That(completeB < completeA, Is.True, $"Das gepufferte PRIORITY_UPDATE (u=0) muss Stream 4 bevorzugen (A: {completeA}, B: {completeB}).");
    }

    // ---- Zustandsmaschine (RFC 9218 §7.2 MUSTs) -------------------------------------------

    [Test]
    public void PriorityUpdate_OnRequestStream_IsFrameUnexpected()
        => AssertServerCloses(client =>
        {
            QuicStream request = client.OpenBidirectionalStream();
            request.Write(Http3Frames.Build(Http3FrameType.PriorityUpdateRequest, [0x00, .. "u=0"u8]));
        }, Http3Error.FrameUnexpected);

    [Test]
    public void PriorityUpdate_ForNonRequestStreamId_IsIdError()
        => AssertServerCloses(client =>
        {
            QuicStream control = client.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
            control.Write(Http3Frames.Build(Http3FrameType.PriorityUpdateRequest, [0x03, .. "u=0"u8])); // 0b11 ≠ Request-Stream
        }, Http3Error.IdError);

    [Test]
    public void PriorityUpdate_PushVariant_IsIdError()
        => AssertServerCloses(client =>
        {
            QuicStream control = client.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
            control.Write(Http3Frames.Build(Http3FrameType.PriorityUpdatePush, [0x00, .. "u=0"u8])); // nie versprochen
        }, Http3Error.IdError);

    [Test]
    public void PriorityUpdate_SentToClient_IsFrameUnexpected()
    {
        // RFC 9218 §7.2: Server MÜSSEN NIE PRIORITY_UPDATE senden — der Client muss schließen.
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump2(client, server);
        client.InitializeHttp3();

        QuicStream control = server.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
        control.Write(Http3Frames.Build(Http3FrameType.PriorityUpdateRequest, [0x00, .. "u=0"u8]));

        for (int round = 0; round < 10 && !client.IsClosing; round++)
            Pump2(client, server);
        Pump2(client, server); // das CONNECTION_CLOSE noch zustellen

        Assert.That(client.IsClosing, Is.True);
        Assert.That(server.PeerCloseFrame, Is.Not.Null);
        Assert.That(server.PeerCloseFrame!.ErrorCode, Is.EqualTo(Http3Error.FrameUnexpected));
    }

    // ---- Helfer ---------------------------------------------------------------------------

    /// <summary>
    /// Zwei große Requests über den eigenen Stack; Rückgabe: Runde der jeweiligen Fertigstellung.
    /// </summary>
    private static (int RoundA, int RoundB) RunTwoRequests(Http3Request first, Http3Request second)
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        byte[] big = new byte[150_000];
        Http3Response Handler(Http3Request request) => new() { Status = 200, Body = big };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        ulong a = client.SendRequest(first);
        ulong b = client.SendRequest(second);
        return AwaitBoth(client, server, a, b);
    }

    private static (int RoundA, int RoundB) AwaitBoth(Http3ClientConnection client, Http3ServerConnection server, ulong a, ulong b)
    {
        int roundA = -1, roundB = -1;
        for (int round = 0; round < 2000 && (roundA < 0 || roundB < 0); round++)
        {
            Pump(client, server);
            if (roundA < 0 && client.TryGetResponse(a, out _)) roundA = round;
            if (roundB < 0 && client.TryGetResponse(b, out _)) roundB = round;
        }
        Assert.That(roundA >= 0 && roundB >= 0, Is.True, "Beide Antworten müssen ankommen.");
        return (roundA, roundB);
    }

    private static byte[] EncodeGet(string path)
        => QpackEncoder.Encode(
        [
            new HeaderField(":method", "GET"),
            new HeaderField(":scheme", "https"),
            new HeaderField(":authority", "localhost"),
            new HeaderField(":path", path),
        ]);

    private static void AssertServerCloses(Action<QuicClientConnection> misbehave, ulong expectedError)
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        using var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] });
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);

        misbehave(client);
        for (int round = 0; round < 10 && !server.IsClosing; round++)
            Pump(client, server);

        Assert.That(server.IsClosing, Is.True, "Der Server muss die Verbindung schließen.");
        Assert.That(client.PeerCloseFrame, Is.Not.Null);
        Assert.That(client.PeerCloseFrame!.IsApplicationError, Is.True);
        Assert.That(client.PeerCloseFrame.ErrorCode, Is.EqualTo(expectedError));
    }

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
