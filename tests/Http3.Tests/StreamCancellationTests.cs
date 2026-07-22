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

using System.Threading;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3;
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.Qpack;
using org.GraphDefined.Vanaheimr.Hermod.Quic;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// RESET_STREAM/STOP_SENDING (RFC 9000 §2.4, §3.5, §19.4/§19.5) und die darauf aufbauende
/// HTTP/3-Request-Cancellation (RFC 9114 §4.1.1).
/// </summary>
[TestFixture]
public class StreamCancellationTests
{
    // ---- Unit: Sende-/Empfangspuffer ------------------------------------------------------

    [Test]
    public void SendBuffer_Reset_DropsPendingData_AndEmitsSingleResetFrame()
    {
        var send = new StreamSendBuffer(4) { MaxData = 100 };
        send.Write([1, 2, 3, 4, 5]);
        Assert.That(send.NextFrame(3), Is.Not.Null); // 3 Bytes gesendet ⇒ Final Size = 3 (RFC 9000 §4.5)

        send.Reset(0x0c);
        Assert.That(send.IsReset, Is.True);
        Assert.That(send.HasPending, Is.False);                    // ungesendete Daten verworfen
        Assert.That(send.NextFrame(100), Is.Null);                 // §19.4: keine STREAM-Frames mehr
        var frame = send.TakeResetFrame();
        Assert.That(frame, Is.Not.Null);
        Assert.That(frame!.FinalSize, Is.EqualTo(3UL));
        Assert.That(frame.ApplicationErrorCode, Is.EqualTo(0x0cUL));
        Assert.That(send.TakeResetFrame(), Is.Null);               // nur einmal abholbar
        send.Write([9]);                                  // nach Reset ignoriert
        Assert.That(send.HasPending, Is.False);
    }

    [Test]
    public void ReceiveBuffer_Reset_ValidatesFinalSize_AndNeverCompletes()
    {
        // Final Size kleiner als bereits Gesehenes ⇒ FINAL_SIZE_ERROR (RFC 9000 §4.5).
        var recv1 = new StreamReceiveBuffer();
        Assert.That(recv1.Receive(0, new byte[10], fin: false), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv1.Reset(0x0c, finalSize: 5), Is.EqualTo(StreamReceiveResult.FinalSizeError));

        // Widerspruch zu bekannter Final Size (FIN) ⇒ FINAL_SIZE_ERROR.
        var recv2 = new StreamReceiveBuffer();
        Assert.That(recv2.Receive(0, new byte[4], fin: true), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv2.Reset(0x0c, finalSize: 8), Is.EqualTo(StreamReceiveResult.FinalSizeError));

        // Final Size über dem Flow-Control-Fenster ⇒ FLOW_CONTROL_ERROR (RFC 9000 §4.1).
        var recv3 = new StreamReceiveBuffer { MaxData = 4 };
        Assert.That(recv3.Reset(0x0c, finalSize: 5), Is.EqualTo(StreamReceiveResult.FlowControlError));

        // Gültiger Reset: gepufferte Daten verworfen, Fehlercode gemerkt, NIE „vollständig".
        var recv4 = new StreamReceiveBuffer();
        Assert.That(recv4.Receive(0, new byte[10], fin: false), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv4.Reset(0x0c, finalSize: 20), Is.EqualTo(StreamReceiveResult.Ok));
        Assert.That(recv4.ResetReceived, Is.True);
        Assert.That(recv4.ResetErrorCode, Is.EqualTo(0x0cUL));
        Assert.That(recv4.ReadAvailable(), Is.Empty);
        Assert.That(recv4.IsComplete, Is.False);
        Assert.That(recv4.BytesConsumed, Is.EqualTo(20UL)); // §4.5: Final Size zählt als verbrauchter Kredit
        Assert.That(recv4.Reset(0x0c, finalSize: 20), Is.EqualTo(StreamReceiveResult.Ok)); // idempotent
    }

    // ---- Integration (QUIC): STOP_SENDING löst RESET_STREAM mit kopiertem Code aus --------

    [Test]
    public void StopSending_SolicitsResetStream_WithCopiedErrorCode()
    {
        (QuicClientConnection client, QuicServerConnection server, ServerCertificate cert) = HandshakeInProcess();
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using QuicServerConnection s = server;

        // Client sendet auf einem Bidi-Stream; der Server bricht das Lesen ab (§3.5).
        QuicStream clientStream = client.OpenBidirectionalStream();
        clientStream.Write([1, 2, 3]);
        for (int round = 0; round < 5; round++)
            Pump(client, server);

        QuicStream serverStream = server.Streams[clientStream.Id.Value];
        serverStream.AbortRead(0x77);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        // Der Client hat das STOP_SENDING erhalten und MUSS mit RESET_STREAM antworten (§3.5),
        // den Fehlercode SOLL er kopieren; der Server sieht den Reset.
        Assert.That(clientStream.PeerStopSendingErrorCode, Is.EqualTo(0x77UL));
        Assert.That(clientStream.Send.IsReset, Is.True);
        Assert.That(serverStream.IsResetByPeer, Is.True);
        Assert.That(serverStream.PeerResetErrorCode, Is.EqualTo(0x77UL));
        Assert.That(server.IsClosing, Is.False);
        Assert.That(client.IsClosing, Is.False);
    }

    [Test]
    public void StopSending_OnReceiveOnlyStream_IsStreamStateError()
    {
        (QuicClientConnection client, QuicServerConnection server, ServerCertificate cert) = HandshakeInProcess();
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using QuicServerConnection s = server;

        // Der Client „missbraucht" die API: STOP_SENDING auf dem EIGENEN Uni-Stream (dort sendet der
        // Peer nie). Der Server MUSS die Verbindung mit STREAM_STATE_ERROR beenden (RFC 9000 §19.5).
        QuicStream uni = client.OpenUnidirectionalStream();
        uni.Write([1]);
        for (int round = 0; round < 5; round++)
            Pump(client, server);
        uni.AbortRead(0x01);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.That(server.IsClosing, Is.True, "Der Server muss wegen STREAM_STATE_ERROR schließen.");
        Assert.That(client.PeerCloseFrame, Is.Not.Null);
        Assert.That(client.PeerCloseFrame!.ErrorCode, Is.EqualTo((ulong)TransportError.StreamStateError));
    }

    [Test]
    public void ResetStream_OnSendOnlyStream_IsStreamStateError()
    {
        (QuicClientConnection client, QuicServerConnection server, ServerCertificate cert) = HandshakeInProcess();
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using QuicServerConnection s = server;

        // Spiegelbild: der Server „resettet" den client-initiierten Uni-Stream, auf dem er nie sendet.
        // Der Client MUSS mit STREAM_STATE_ERROR schließen (RFC 9000 §19.4).
        QuicStream uni = client.OpenUnidirectionalStream();
        uni.Write([1]);
        for (int round = 0; round < 5; round++)
            Pump(client, server);
        server.Streams[uni.Id.Value].Reset(0x01);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.That(client.IsClosing, Is.True, "Der Client muss wegen STREAM_STATE_ERROR schließen.");
        Assert.That(server.PeerCloseFrame, Is.Not.Null);
        Assert.That(server.PeerCloseFrame!.ErrorCode, Is.EqualTo((ulong)TransportError.StreamStateError));
    }

    // ---- Integration (HTTP/3): Request-Cancellation (RFC 9114 §4.1.1) ---------------------

    [Test]
    public void CancelRequest_MidResponse_StopsServer_AndConnectionRemainsUsable()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        byte[] bigBody = new byte[300_000];
        Http3Response Handler(Http3Request request) => new()
        {
            Status = 200,
            Body = request.Path == "/big" ? bigBody : System.Text.Encoding.UTF8.GetBytes("klein"),
        };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        // Große Antwort anfordern, nur kurz laufen lassen (Slow Start ⇒ erst ein Bruchteil da) …
        ulong streamId = client.SendRequest(Http3Request.Get("localhost", "/big"));
        for (int round = 0; round < 3; round++)
            Pump(client, server);
        Assert.That(client.TryGetResponse(streamId, out _), Is.False);

        // … und abbrechen (§4.1.1: RESET_STREAM + STOP_SENDING mit H3_REQUEST_CANCELLED).
        client.CancelRequest(streamId);
        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.That(client.IsRequestCancelled(streamId), Is.True);
        Assert.That(client.TryGetResponse(streamId, out _), Is.False);
        // Der Server hat seine Antwortseite zurückgesetzt und sendet nichts mehr auf dem Stream.
        QuicStream serverStream = server.Quic.Streams[streamId];
        Assert.That(serverStream.Send.IsReset, Is.True);
        Assert.That(serverStream.Send.HasPending, Is.False, "Ungesendete Antwortdaten müssen verworfen sein.");
        // Der Client sieht den Server-Reset (H3_REQUEST_CANCELLED, via kopiertem STOP_SENDING-Code).
        Assert.That(client.RequestResetErrorCode(streamId), Is.EqualTo(Http3Error.RequestCancelled));

        // Die VERBINDUNG lebt weiter: ein zweiter Request läuft normal durch.
        ulong second = client.SendRequest(Http3Request.Get("localhost", "/small"));
        Http3Response? response = null;
        for (int round = 0; round < 50 && response is null; round++)
        {
            Pump(client, server);
            client.TryGetResponse(second, out response);
        }
        Assert.That(response, Is.Not.Null);
        Assert.That(response!.Status, Is.EqualTo(200));
        Assert.That(response.BodyText, Is.EqualTo("klein"));
    }

    [Test]
    public void CancelRequest_SurvivesPacketLoss_ViaRetransmission()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");

        byte[] bigBody = new byte[300_000];
        Http3Response Handler(Http3Request request) => new() { Status = 200, Body = bigBody };

        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var server = new Http3ServerConnection(cert, Handler);
        using var client = new Http3ClientConnection("localhost", certificateValidation: validation);
        client.Start();

        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();

        ulong streamId = client.SendRequest(Http3Request.Get("localhost", "/big"));
        for (int round = 0; round < 3; round++)
            Pump(client, server);

        client.CancelRequest(streamId);

        // Den ERSTEN Client-Flight nach dem Abbruch (trägt RESET_STREAM + STOP_SENDING) verwerfen —
        // die Loss Recovery (PTO) muss beide Frames zuverlässig nachliefern (RFC 9000 §19.4/§3.5).
        client.CheckTimeouts();
        foreach (byte[] _ in client.GetDatagramsToSend()) { /* verworfen */ }

        QuicStream serverStream = server.Quic.Streams[streamId];
        for (int round = 0; round < 40 && !serverStream.IsResetByPeer; round++)
        {
            Thread.Sleep(30); // PTO verstreichen lassen
            client.CheckTimeouts();
            foreach (byte[] dg in client.GetDatagramsToSend())
                server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
        }

        Assert.That(serverStream.IsResetByPeer, Is.True, "Das RESET_STREAM muss per Retransmission ankommen.");
        Assert.That(serverStream.Send.IsReset, Is.True, "Das STOP_SENDING muss per Retransmission ankommen.");
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

    private static void Pump(Http3ClientConnection client, Http3ServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend())
            server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend())
            client.ProcessDatagram(dg);
    }
}
