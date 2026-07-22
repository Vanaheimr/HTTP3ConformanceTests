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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Frame-/Stream-Zustandsmaschine von HTTP/3 (RFC 9114 §4.1, §6.2, §7.2): Protokollverstöße der
/// Gegenseite MÜSSEN als Verbindungsfehler mit dem passenden H3-Fehlercode (§8.1) beantwortet werden —
/// als CONNECTION_CLOSE Typ 0x1d (Application Error). Der „böse" Peer wird jeweils mit einer rohen
/// QUIC-Verbindung nachgestellt, die von Hand HTTP/3-Bytes schreibt.
/// </summary>
[TestFixture]
public class Http3FrameStateMachineTests
{
    // ---- Verstöße des Clients ⇒ der SERVER muss schließen ---------------------------------

    [Test]
    public void DataBeforeHeaders_OnRequestStream_IsFrameUnexpected()
        => AssertServerCloses(
            client => client.OpenBidirectionalStream().Write(Http3Frames.Build(Http3FrameType.Data, [1, 2, 3])),
            Http3Error.FrameUnexpected);

    [Test]
    public void ReservedHttp2FrameType_OnRequestStream_IsFrameUnexpected()
        => AssertServerCloses( // 0x06 war HTTP/2 PING — in HTTP/3 reserviert (§7.2.8)
            client => client.OpenBidirectionalStream().Write(Http3Frames.Build(0x06, [])),
            Http3Error.FrameUnexpected);

    [Test]
    public void Settings_OnRequestStream_IsFrameUnexpected()
        => AssertServerCloses(
            client => client.OpenBidirectionalStream().Write(Http3Frames.Build(Http3FrameType.Settings, [])),
            Http3Error.FrameUnexpected);

    [Test]
    public void PushPromise_FromClient_IsFrameUnexpected()
        => AssertServerCloses(
            client => client.OpenBidirectionalStream().Write(Http3Frames.Build(Http3FrameType.PushPromise, [0x00])),
            Http3Error.FrameUnexpected);

    [Test]
    public void ControlStream_FirstFrameNotSettings_IsMissingSettings()
        => AssertServerCloses(client =>
        {
            QuicStream control = client.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.GoAway, [0x00]));
        }, Http3Error.MissingSettings);

    [Test]
    public void SecondControlStream_IsStreamCreationError()
        => AssertServerCloses(client =>
        {
            QuicStream first = client.OpenUnidirectionalStream();
            first.Write([(byte)Http3StreamType.Control]);
            first.Write(Http3Frames.Build(Http3FrameType.Settings, []));
            QuicStream second = client.OpenUnidirectionalStream();
            second.Write([(byte)Http3StreamType.Control]);
        }, Http3Error.StreamCreationError);

    [Test]
    public void ClientInitiatedPushStream_IsStreamCreationError()
        => AssertServerCloses(
            client => client.OpenUnidirectionalStream().Write([(byte)Http3StreamType.Push]),
            Http3Error.StreamCreationError);

    [Test]
    public void ReservedHttp2Setting_IsSettingsError()
        => AssertServerCloses(client =>
        {
            QuicStream control = client.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, BuildSettingsPayload((0x02, 0)))); // reserviert
        }, Http3Error.SettingsError);

    [Test]
    public void DuplicateSettingIdentifier_IsSettingsError()
        => AssertServerCloses(client =>
        {
            QuicStream control = client.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings,
                BuildSettingsPayload((Http3Setting.QpackMaxTableCapacity, 0), (Http3Setting.QpackMaxTableCapacity, 0))));
        }, Http3Error.SettingsError);

    [Test]
    public void ClosingControlStream_IsClosedCriticalStream()
        => AssertServerCloses(client =>
        {
            QuicStream control = client.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
            control.Finish(); // §6.2.1: der Control-Stream darf NIE enden
        }, Http3Error.ClosedCriticalStream);

    [Test]
    public void TruncatedFrame_AtCleanStreamEnd_IsFrameError()
        => AssertServerCloses(client =>
        {
            QuicStream stream = client.OpenBidirectionalStream();
            // Frame-Kopf verspricht 10 Nutzlast-Bytes, es folgen nur 3 — dann sauberes FIN (§7.1).
            stream.Write([(byte)Http3FrameType.Data, 10, 1, 2, 3]);
            stream.Finish();
        }, Http3Error.FrameError);

    // ---- Toleranz: Grease MUSS ignoriert werden (§7.2.8, §7.2.4.1, §9) --------------------

    [Test]
    public void GreaseFrameAndGreaseSetting_AreIgnored_RequestSucceeds()
    {
        bool handled = false;
        (QuicClientConnection client, Http3ServerConnection server, ServerCertificate cert) =
            RawClientHandshake(_ => { handled = true; });
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using Http3ServerConnection s = server;

        // Control-Stream mit SETTINGS samt Grease-Setting (0x1f·N + 0x21).
        QuicStream control = client.OpenUnidirectionalStream();
        control.Write([(byte)Http3StreamType.Control]);
        control.Write(Http3Frames.Build(Http3FrameType.Settings, BuildSettingsPayload((0x1f * 7 + 0x21, 42))));

        // Request-Stream: erst ein Grease-Frame (0x21), dann echte HEADERS (statisch kodiert), FIN.
        QuicStream request = client.OpenBidirectionalStream();
        request.Write(Http3Frames.Build(0x21, [0xaa, 0xbb]));
        byte[] headerBlock = QpackEncoder.Encode(
        [
            new HeaderField(":method", "GET"),
            new HeaderField(":scheme", "https"),
            new HeaderField(":authority", "localhost"),
            new HeaderField(":path", "/"),
        ]);
        request.Write(Http3Frames.Build(Http3FrameType.Headers, headerBlock));
        request.Finish();

        for (int round = 0; round < 10; round++)
            Pump(client, server);

        Assert.That(handled, Is.True, "Der Request muss trotz Grease-Frame/-Setting beantwortet werden.");
        Assert.That(server.IsClosing, Is.False, "Grease darf KEIN Verbindungsfehler sein (§9).");
    }

    // ---- Verstöße des Servers ⇒ der CLIENT muss schließen ---------------------------------

    [Test]
    public void MaxPushId_SentToClient_IsFrameUnexpected()
        => AssertClientCloses(server =>
        {
            QuicStream control = server.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
            control.Write(Http3Frames.Build(Http3FrameType.MaxPushId, [0x08])); // §7.2.7: nur Client→Server
        }, Http3Error.FrameUnexpected);

    [Test]
    public void GoAway_WithNonRequestStreamId_IsIdError()
        => AssertClientCloses(server =>
        {
            QuicStream control = server.OpenUnidirectionalStream();
            control.Write([(byte)Http3StreamType.Control]);
            control.Write(Http3Frames.Build(Http3FrameType.Settings, []));
            control.Write(Http3Frames.Build(Http3FrameType.GoAway, [0x03])); // 0b11 = server-uni ⇒ illegal (§7.2.6)
        }, Http3Error.IdError);

    // ---- Helfer ---------------------------------------------------------------------------

    /// <summary>
    /// Roher QUIC-Client gegen unseren HTTP/3-Server: <paramref name="misbehave"/> schreibt die bösen
    /// Bytes, danach MUSS der Server mit dem H3-Fehlercode <paramref name="expectedError"/> schließen.
    /// </summary>
    private static void AssertServerCloses(Action<QuicClientConnection> misbehave, ulong expectedError)
    {
        (QuicClientConnection client, Http3ServerConnection server, ServerCertificate cert) = RawClientHandshake(null);
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using Http3ServerConnection s = server;

        misbehave(client);
        for (int round = 0; round < 10 && !server.IsClosing; round++)
            Pump(client, server);

        Assert.That(server.IsClosing, Is.True, "Der Server muss die Verbindung schließen.");
        Assert.That(client.PeerCloseFrame, Is.Not.Null);
        Assert.That(client.PeerCloseFrame!.IsApplicationError, Is.True, "H3-Fehler sind Application Errors (Typ 0x1d).");
        Assert.That(client.PeerCloseFrame.ErrorCode, Is.EqualTo(expectedError));
    }

    /// <summary>
    /// Roher QUIC-Server gegen unseren HTTP/3-Client: <paramref name="misbehave"/> schreibt die bösen
    /// Bytes, danach MUSS der Client mit dem H3-Fehlercode <paramref name="expectedError"/> schließen.
    /// </summary>
    private static void AssertClientCloses(Action<QuicServerConnection> misbehave, ulong expectedError)
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

        misbehave(server);
        for (int round = 0; round < 10 && !client.IsClosing; round++)
            Pump(client, server);
        Pump(client, server); // das CONNECTION_CLOSE des Clients noch zustellen

        Assert.That(client.IsClosing, Is.True, "Der Client muss die Verbindung schließen.");
        Assert.That(server.PeerCloseFrame, Is.Not.Null);
        Assert.That(server.PeerCloseFrame!.IsApplicationError, Is.True, "H3-Fehler sind Application Errors (Typ 0x1d).");
        Assert.That(server.PeerCloseFrame.ErrorCode, Is.EqualTo(expectedError));
    }

    private static (QuicClientConnection, Http3ServerConnection, ServerCertificate) RawClientHandshake(Action<Http3Request>? onRequest)
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var server = new Http3ServerConnection(cert, request =>
        {
            onRequest?.Invoke(request);
            return new Http3Response { Status = 200, Body = [] };
        });
        var client = new QuicClientConnection("localhost", certificateValidation: validation);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
            Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        return (client, server, cert);
    }

    private static byte[] BuildSettingsPayload(params (ulong Id, ulong Value)[] settings)
    {
        var writer = new BufferWriter(32);
        try
        {
            foreach ((ulong id, ulong value) in settings)
            {
                writer.WriteVarInt(id);
                writer.WriteVarInt(value);
            }
            return writer.WrittenSpan.ToArray();
        }
        finally { writer.Dispose(); }
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
