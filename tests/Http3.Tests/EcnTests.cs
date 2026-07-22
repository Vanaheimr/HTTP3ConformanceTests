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
using org.GraphDefined.Vanaheimr.Hermod.Quic.Recovery;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

/// <summary>
/// ECN (RFC 9000 §13.4 / RFC 9002 §7.3): der Empfänger zählt die ECN-Codepoints je Packet-Number-Space und
/// meldet sie im ACK-Frame (Typ 0x03); der Sender behandelt einen gestiegenen CE-Zähler wie einen Verlust und
/// verkleinert das Congestion Window. Unit-Tests für Zählung/Meldung und CE-Reaktion plus ein End-to-End-Test.
/// </summary>
public class EcnTests
{
    [Fact]
    public void PacketNumberSpace_CountsEcnCodepoints_AndReportsThemInAck()
    {
        var space = new PacketNumberSpace();
        space.RecordReceived(0, EcnCodepoint.Ect0);
        space.RecordReceived(1, EcnCodepoint.Ect0);
        space.RecordReceived(2, EcnCodepoint.Ce);

        AckFrame? ack = space.BuildAck();
        Assert.NotNull(ack);
        Assert.NotNull(ack!.Ecn);
        Assert.Equal(2ul, ack.Ecn!.Value.Ect0);
        Assert.Equal(0ul, ack.Ecn.Value.Ect1);
        Assert.Equal(1ul, ack.Ecn.Value.CongestionExperienced);
    }

    [Fact]
    public void PacketNumberSpace_WithoutEcnMarks_BuildsPlainAck()
    {
        var space = new PacketNumberSpace();
        space.RecordReceived(0); // Not-ECT
        space.RecordReceived(1);

        AckFrame? ack = space.BuildAck();
        Assert.NotNull(ack);
        Assert.Null(ack!.Ecn); // Typ 0x02, keine ECN-Zähler
    }

    [Fact]
    public void LossRecovery_OnIncreasedCeCount_ReducesCongestionWindow()
    {
        var recovery = new LossRecovery();
        recovery.OnPacketSent(space: 0, new SentPacket
        {
            PacketNumber = 0, TimeSentTicks = 0, AckEliciting = true, Size = 1200, RetransmittableFrames = [],
        });
        long before = recovery.Congestion.CongestionWindow;

        // ACK bestätigt Paket 0 UND meldet einen CE-Zähler von 1 ⇒ Congestion-Signal.
        var ack = new AckFrame([new PacketNumberRange(0, 0)], 0, new EcnCounts(0, 0, 1));
        recovery.OnAckReceived(space: 0, ack, System.TimeSpan.Zero, nowTicks: 1000);

        Assert.True(recovery.Congestion.CongestionWindow < before,
            $"Ein gestiegener CE-Zähler muss das Fenster verkleinern (war {before}, ist {recovery.Congestion.CongestionWindow}).");
    }

    [Fact]
    public void LossRecovery_SameCeCount_DoesNotReduceTwice()
    {
        var recovery = new LossRecovery();
        recovery.OnPacketSent(0, new SentPacket { PacketNumber = 0, TimeSentTicks = 0, AckEliciting = true, Size = 1200, RetransmittableFrames = [] });
        recovery.OnPacketSent(0, new SentPacket { PacketNumber = 1, TimeSentTicks = 0, AckEliciting = true, Size = 1200, RetransmittableFrames = [] });

        recovery.OnAckReceived(0, new AckFrame([new PacketNumberRange(0, 0)], 0, new EcnCounts(0, 0, 1)), System.TimeSpan.Zero, 1000);
        long afterFirst = recovery.Congestion.CongestionWindow;
        // Zweites ACK mit UNVERÄNDERTEM CE-Zähler ⇒ kein erneutes Verkleinern.
        recovery.OnAckReceived(0, new AckFrame([new PacketNumberRange(1, 1)], 0, new EcnCounts(0, 0, 1)), System.TimeSpan.Zero, 2000);

        Assert.True(recovery.Congestion.CongestionWindow >= afterFirst, "Gleicher CE-Zähler darf nicht erneut verkleinern.");
    }

    [Fact]
    public void CeMarkedPackets_ReportedByPeer_ReduceSendersCongestionWindow()
    {
        using var cert = ServerCertificate.CreateSelfSigned("localhost");
        var validation = new CertificateValidationOptions { CustomTrustRoots = [cert.Certificate] };
        using var client = new QuicClientConnection("localhost", certificateValidation: validation);
        using var server = new QuicServerConnection(cert);
        client.Start();

        long prevCwnd = client.CongestionWindow;
        bool cwndDropped = false;

        // Alle Client→Server-Datagramme als CE markieren ⇒ der Server meldet CE in seinen ACKs zurück,
        // woraufhin der Client (RFC 9002 §7.3) das Fenster verkleinert. Da in-process kein echter Verlust
        // auftritt, kann ein Fenster-Rückgang nur von der CE-Reaktion stammen.
        for (int round = 0; round < 30; round++)
        {
            foreach (byte[] dg in client.GetDatagramsToSend()) server.ProcessDatagram(dg, EcnCodepoint.Ce);
            foreach (byte[] dg in server.GetDatagramsToSend()) client.ProcessDatagram(dg);
            if (client.CongestionWindow < prevCwnd)
                cwndDropped = true;
            prevCwnd = client.CongestionWindow;
        }

        Assert.True(client.HandshakeConfirmed, "Handshake muss zustande kommen.");
        Assert.True(server.ApplicationReceivedCeCount > 0, "Der Server muss CE-markierte 1-RTT-Pakete gezählt haben.");
        Assert.True(cwndDropped, "Die CE-Meldung des Servers muss das Congestion Window des Clients verkleinern.");
    }
}
