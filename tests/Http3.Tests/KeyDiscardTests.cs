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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// Nach dem Handshake dürfen keine Initial-/Handshake-Pakete mehr gesendet werden (RFC 9001 §4.9.1/§4.9.2:
/// der Client verwirft die Initial-Keys, sobald er ein Handshake-Paket sendet, und die Handshake-Keys, sobald
/// der Handshake bestätigt ist). Sonst sondiert ein PTO fälschlich den Initial-Space und der ClientHello geht
/// als (auf 1200 Byte gepolstertes) Initial erneut raus.
/// </summary>
[TestFixture]
public class KeyDiscardTests
{
    private static bool IsInitial(byte[] dg) =>
        dg.Length > 0 && PacketFormat.IsLongHeader(dg[0]) && PacketFormat.GetLongPacketType(dg[0]) == LongPacketType.Initial;

    private static bool IsHandshake(byte[] dg) =>
        dg.Length > 0 && PacketFormat.IsLongHeader(dg[0]) && PacketFormat.GetLongPacketType(dg[0]) == LongPacketType.Handshake;

    [Test]
    public void AfterHandshake_ClientSendsNoInitialOrHandshakePackets_EvenUnderPto()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);

        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }
        Assert.That(client.HandshakeConfirmed, Is.True);

        // Ack-eliciting 1-RTT-Daten erzeugen, die NICHT bestätigt werden (Server bekommt nichts mehr) ⇒ PTO feuert.
        QuicStream stream = client.OpenBidirectionalStream();
        stream.Write("ping"u8.ToArray());

        bool initialSeen = false, handshakeSeen = false;
        for (int round = 0; round < 40; round++)
        {
            client.CheckLossDetectionTimeout(); // treibt PTO/Loss Detection
            foreach (byte[] dg in client.GetDatagramsToSend())
            {
                initialSeen |= IsInitial(dg);
                handshakeSeen |= IsHandshake(dg);
            }
            Thread.Sleep(20); // realer Uhr Zeit für die PTO-Deadline geben
        }

        Assert.That(initialSeen, Is.False, "Nach dem Handshake darf KEIN Initial-Paket mehr gesendet werden (RFC 9001 §4.9.1).");
        Assert.That(handshakeSeen, Is.False, "Nach dem Handshake darf KEIN Handshake-Paket mehr gesendet werden (RFC 9001 §4.9.2).");
    }

    /// <summary>
    /// Gegenprobe zur „nicht zu spät"-Regel: Die Initial-Keys dürfen auch nicht ZU FRÜH verworfen werden. Der
    /// Client muss den Server-Initial (ServerHello) noch acken können (RFC 9001 §4.9), also ein zweites Initial-
    /// Paket senden. Würde man die Keys schon beim Installieren der Handshake-Keys verwerfen, entfiele dieser ACK.
    /// </summary>
    [Test]
    public void DuringHandshake_ClientSendsInitialAckForServerHello_KeysNotDiscardedTooEarly()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);

        client.Start();
        int clientInitialPackets = 0;
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend())
            {
                if (IsInitial(dg))
                    clientInitialPackets++;
                server.ProcessDatagram(dg);
            }
            foreach (byte[] dg in server.GetDatagramsToSend())
                client.ProcessDatagram(dg);
        }

        Assert.That(client.HandshakeConfirmed, Is.True);
        // ClientHello (≥1 Initial) UND ein Initial-ACK des ServerHello ⇒ mindestens zwei Initial-Pakete.
        Assert.That(clientInitialPackets >= 2, Is.True, $"Der Client muss den Server-Initial noch acken (≥2 Initial-Pakete), sonst wurden die Keys zu früh verworfen. Waren: {clientInitialPackets}.");
    }

    /// <summary>
    /// RFC 9001 §4.1.2: Der Client DARF den Handshake bestätigen, sobald eines seiner 1-RTT-Pakete quittiert wird —
    /// auch ohne HANDSHAKE_DONE. Damit werden die Handshake-Keys ggf. früher (bzw. trotz verlorenem HANDSHAKE_DONE)
    /// verworfen. Der Server unterdrückt hier HANDSHAKE_DONE, damit NUR der 1-RTT-ACK-Pfad die Bestätigung auslöst.
    /// </summary>
    [Test]
    public void ClientConfirmsHandshake_ViaOneRttAck_EvenWithoutHandshakeDone()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert) { SuppressHandshakeDoneForTest = true };

        client.Start();
        for (int round = 0; round < 20 && !client.HandshakeComplete; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }
        Assert.That(client.HandshakeComplete, Is.True, "Der Client muss seinen Finished gesendet haben.");
        Assert.That(client.HandshakeConfirmed, Is.False, "Ohne HANDSHAKE_DONE ist der Handshake noch NICHT bestätigt.");

        // Der Client sendet 1-RTT-Daten; deren ACK (kein HANDSHAKE_DONE!) bestätigt den Handshake (§4.1.2).
        QuicStream stream = client.OpenBidirectionalStream();
        stream.Write("hi"u8.ToArray());
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }

        Assert.That(client.HandshakeConfirmed, Is.True, "Der Client muss den Handshake allein per 1-RTT-ACK bestätigen (RFC 9001 §4.1.2), ohne HANDSHAKE_DONE.");
    }

    /// <summary>
    /// RFC 9001 §4.9.2: Die Handshake-Keys werden bei der Bestätigung SOFORT verworfen – ohne Aufbewahrungs-
    /// fenster. Anders als §4.9.3 für 0-RTT (dort dürfen Server die Keys ~3×PTO gegen Reordering behalten) gibt
    /// es für Handshake-Keys bewusst KEIN Reordering-Fenster: der Handshake ist beidseitig fertig, ein spät
    /// reordertes Handshake-Paket trüge nur schon Bekanntes. Der Test belegt: im selben Moment, in dem der
    /// Handshake bestätigt ist, sind die Handshake-Keys bereits weg.
    /// </summary>
    [Test]
    public void HandshakeKeys_DiscardedImmediatelyOnConfirmation_NoReorderingWindow()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);

        client.Start();
        bool hadHandshakeKeysBeforeConfirm = false;
        for (int round = 0; round < 20 && !client.HandshakeConfirmed; round++)
        {
            // Vor der Bestätigung müssen die Handshake-Keys mindestens einmal installiert gewesen sein.
            hadHandshakeKeysBeforeConfirm |= client.HasHandshakeKeysForTest;
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
        }

        Assert.That(client.HandshakeConfirmed, Is.True);
        Assert.That(hadHandshakeKeysBeforeConfirm, Is.True, "Die Handshake-Keys müssen während des Handshakes installiert gewesen sein.");
        Assert.That(client.HasHandshakeKeysForTest, Is.False, "Mit der Bestätigung müssen die Handshake-Keys SOFORT verworfen sein – kein Reordering-Fenster (RFC 9001 §4.9.2).");
        // Auch der Server verwirft sie mit dem Handshake-Abschluss sofort.
        Assert.That(server.HasHandshakeKeysForTest, Is.False, "Auch der Server verwirft die Handshake-Keys sofort bei Abschluss (RFC 9001 §4.9.2).");
    }
}
