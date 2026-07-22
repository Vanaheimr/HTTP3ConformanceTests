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
using org.GraphDefined.Vanaheimr.Hermod.HTTP3.WebTransport;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// TLS-Keying-Material-Exporter (RFC 8446 §7.5) über <c>exporter_master_secret</c> (§7.1) und der
/// darauf aufbauende session-gebundene WebTransport-Exporter (draft-ietf-webtrans-http3-13 §4.7).
/// </summary>
[TestFixture]
public class KeyingMaterialExportTests
{
    // ---- Unit: exporter_master_secret gegen RFC 8448 §3 ------------------------------------

    [Test]
    public void ExporterMasterSecret_MatchesRfc8448()
    {
        // RFC 8448 §3 („Simple 1-RTT Handshake"): derive secret "tls13 exp master" —
        // PRK = Master Secret, Hash = Transcript über CH…server Finished.
        var ks = new KeySchedule(CipherSuite.Aes128GcmSha256);
        byte[] master = Hex.Parse("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        byte[] transcript = Hex.Parse("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

        Assert.That(Hex.ToHex(ks.ExporterMasterSecret(master, transcript)),
                    Is.EqualTo("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"));
    }

    [Test]
    public void ExportKeyingMaterial_IsDeterministic_AndSeparatesLabelAndContext()
    {
        var ks = new KeySchedule(CipherSuite.Aes128GcmSha256);
        byte[] secret = Hex.Parse("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50");

        byte[] a1 = ks.ExportKeyingMaterial(secret, "EXPORTER-Test", [1, 2, 3], 32);
        byte[] a2 = ks.ExportKeyingMaterial(secret, "EXPORTER-Test", [1, 2, 3], 32);
        Assert.That(a1, Is.EqualTo(a2));                 // deterministisch
        Assert.That(a1, Has.Length.EqualTo(32));

        byte[] otherLabel = ks.ExportKeyingMaterial(secret, "EXPORTER-Anders", [1, 2, 3], 32);
        byte[] otherContext = ks.ExportKeyingMaterial(secret, "EXPORTER-Test", [9, 9, 9], 32);
        byte[] emptyContext = ks.ExportKeyingMaterial(secret, "EXPORTER-Test", [], 32);
        Assert.That(otherLabel, Is.Not.EqualTo(a1));     // Label trennt
        Assert.That(otherContext, Is.Not.EqualTo(a1));   // Kontext trennt
        Assert.That(emptyContext, Is.Not.EqualTo(a1));
    }

    // ---- Integration (QUIC): beide Enden exportieren identisches Material -------------------

    [Test]
    public void QuicConnection_BothEndsExportIdenticalMaterial()
    {
        (QuicClientConnection client, QuicServerConnection server, ServerCertificate cert) = HandshakeInProcess();
        using ServerCertificate _ = cert;
        using QuicClientConnection c = client;
        using QuicServerConnection s = server;

        byte[] clientSide = client.ExportKeyingMaterial("EXPORTER-Test", [0xAA, 0xBB], 32);
        byte[] serverSide = server.ExportKeyingMaterial("EXPORTER-Test", [0xAA, 0xBB], 32);
        Assert.That(clientSide, Is.EqualTo(serverSide)); // der Kern von §7.5: beide Seiten stimmen überein

        Assert.That(client.ExportKeyingMaterial("EXPORTER-Test", [0xAA, 0xBB], 48), Has.Length.EqualTo(48));
        Assert.That(client.ExportKeyingMaterial("EXPORTER-Zwei", [0xAA, 0xBB], 32), Is.Not.EqualTo(clientSide));
    }

    [Test]
    public void Export_BeforeHandshake_Throws()
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        using ServerCertificate _ = cert;
        using var server = new QuicServerConnection(cert);
        Assert.Throws<InvalidOperationException>(() => server.ExportKeyingMaterial("EXPORTER-Test", [], 32));
    }

    // ---- Integration (WebTransport §4.7): session-gebundene Exporte -------------------------

    [Test]
    public void WebTransportSessions_ExportMatchingMaterial_ButSeparatePerSession()
    {
        var serverSessions = new List<WebTransportSession>();
        (Http3ClientConnection client, Http3ServerConnection server, ServerCertificate cert) = Pair(serverSessions);
        using ServerCertificate certGuard = cert;
        using Http3ClientConnection c = client;
        using Http3ServerConnection s = server;

        WebTransportSession client1 = Establish(client, server, "/wt");
        WebTransportSession client2 = Establish(client, server, "/wt");
        Assert.That(serverSessions, Has.Count.EqualTo(2));

        byte[] context = [1, 2, 3];
        byte[] c1 = client1.ExportKeyingMaterial("app-label", context, 32);
        byte[] s1 = serverSessions[0].ExportKeyingMaterial("app-label", context, 32);
        byte[] c2 = client2.ExportKeyingMaterial("app-label", context, 32);
        byte[] s2 = serverSessions[1].ExportKeyingMaterial("app-label", context, 32);

        Assert.That(c1, Is.EqualTo(s1)); // beide Enden derselben Session stimmen überein …
        Assert.That(c2, Is.EqualTo(s2));
        Assert.That(c1, Is.Not.EqualTo(c2)); // … verschiedene Sessions derselben Verbindung nicht (§4.7)

        // Label-/Kontext-Trennung auch auf Session-Ebene.
        Assert.That(client1.ExportKeyingMaterial("anderes-label", context, 32), Is.Not.EqualTo(c1));
        Assert.That(client1.ExportKeyingMaterial("app-label", [9], 32), Is.Not.EqualTo(c1));

        // draft §4.7: Label 1–255 Bytes, Kontext 0–255 Bytes.
        Assert.Throws<ArgumentException>(() => client1.ExportKeyingMaterial("", [], 32));
        Assert.Throws<ArgumentException>(() => client1.ExportKeyingMaterial(new string('x', 256), [], 32));
        Assert.Throws<ArgumentException>(() => client1.ExportKeyingMaterial("ok", new byte[256], 32));
    }

    // ---- Helfer ---------------------------------------------------------------------------

    private static (QuicClientConnection, QuicServerConnection, ServerCertificate) HandshakeInProcess()
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var client = new QuicClientConnection("localhost", certificateValidation: validation);
        var server = new QuicServerConnection(cert);
        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++) Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        return (client, server, cert);
    }

    private static (Http3ClientConnection, Http3ServerConnection, ServerCertificate) Pair(List<WebTransportSession> serverSessions)
    {
        var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        var server = new Http3ServerConnection(cert, _ => new Http3Response { Status = 200, Body = [] },
            webTransportMaxSessions: 4, webTransportHandler: _ => serverSessions.Add);
        var client = new Http3ClientConnection("localhost", certificateValidation: validation, webTransportMaxSessions: 4);
        client.Start();
        for (int r = 0; r < 20 && !client.HandshakeConfirmed; r++) Pump(client, server);
        Assert.That(client.HandshakeConfirmed, Is.True);
        client.InitializeHttp3();
        for (int r = 0; r < 5; r++) Pump(client, server); // SETTINGS beidseitig
        return (client, server, cert);
    }

    private static WebTransportSession Establish(Http3ClientConnection client, Http3ServerConnection server, string path)
    {
        ulong id = client.ConnectWebTransport("localhost", path);
        WebTransportSession? session = null;
        for (int r = 0; r < 20 && session is null; r++) { Pump(client, server); client.TryGetWebTransportSession(id, out session); }
        Assert.That(session, Is.Not.Null);
        return session!;
    }

    private static void Pump(QuicClientConnection client, QuicServerConnection server)
    {
        client.CheckLossDetectionTimeout();
        foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
    }

    private static void Pump(Http3ClientConnection client, Http3ServerConnection server)
    {
        client.CheckTimeouts();
        foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
        foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
    }
}
