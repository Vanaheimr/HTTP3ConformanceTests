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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Recovery;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.HTTP3.Tests;

public class RttEstimatorTests
{
    private static TimeSpan Ms(double ms) => TimeSpan.FromMilliseconds(ms);

    [Fact]
    public void FirstSample_InitializesSmoothedAndVar()
    {
        var rtt = new RttEstimator();
        rtt.AddSample(Ms(100), ackDelay: Ms(0), maxAckDelay: Ms(25));

        Assert.Equal(Ms(100), rtt.MinRtt);
        Assert.Equal(Ms(100), rtt.SmoothedRtt);
        Assert.Equal(Ms(50), rtt.RttVar);
    }

    [Fact]
    public void SubsequentSample_SmoothsToward_AndAppliesAckDelay()
    {
        var rtt = new RttEstimator();
        rtt.AddSample(Ms(100), Ms(0), Ms(25));
        rtt.AddSample(Ms(140), ackDelay: Ms(20), maxAckDelay: Ms(25)); // adjusted = 120

        // smoothed = 7/8*100 + 1/8*120 = 102.5 ms
        Assert.Equal(Ms(102.5), rtt.SmoothedRtt);
        Assert.Equal(Ms(100), rtt.MinRtt);
    }

    [Fact]
    public void Pto_UsesInitialRtt_BeforeAnySample()
    {
        var rtt = new RttEstimator();
        Assert.Equal(2 * RttEstimator.InitialRtt, rtt.GetProbeTimeout(Ms(25)));
    }
}

public class NewRenoTests
{
    [Fact]
    public void SlowStart_GrowsWindowByAckedBytes()
    {
        var cc = new NewRenoCongestionControl();
        int start = cc.CongestionWindow;
        cc.OnPacketSent(1200);
        cc.OnPacketAcked(1200, sentTimeTicks: 100);

        Assert.True(cc.InSlowStart);
        Assert.Equal(start + 1200, cc.CongestionWindow);
        Assert.Equal(0, cc.BytesInFlight);
    }

    [Fact]
    public void Loss_HalvesWindow_AndEntersRecovery()
    {
        var cc = new NewRenoCongestionControl();
        int start = cc.CongestionWindow;
        cc.OnPacketSent(1200);
        cc.OnPacketsLost(1200, largestLostSentTimeTicks: 100, nowTicks: 200);

        Assert.Equal(start / 2, cc.SlowStartThreshold);
        Assert.Equal(Math.Max(start / 2, NewRenoCongestionControl.MinimumWindow), cc.CongestionWindow);
        Assert.False(cc.InSlowStart);
    }

    [Fact]
    public void CanSend_BlocksWhenBytesInFlightReachWindow()
    {
        var cc = new NewRenoCongestionControl();
        int window = cc.CongestionWindow;

        cc.OnPacketSent(window); // Fenster genau ausgefüllt
        Assert.Equal(0, cc.Available);
        Assert.False(cc.CanSend(1));   // nichts Neues mehr erlaubt
        Assert.True(cc.CanSend(0));

        cc.OnPacketAcked(window, sentTimeTicks: 1); // wieder freigegeben
        Assert.True(cc.Available > 0);
        Assert.True(cc.CanSend(1));
    }

    [Fact]
    public void PersistentCongestion_CollapsesWindowToMinimum_AndRestartsSlowStart()
    {
        var cc = new NewRenoCongestionControl();
        cc.OnPacketSent(20_000);
        cc.OnPacketsLost(20_000, largestLostSentTimeTicks: 100, nowTicks: 200); // ssthresh gesetzt, nicht Slow Start

        cc.OnPersistentCongestion();

        Assert.Equal(NewRenoCongestionControl.MinimumWindow, cc.CongestionWindow);
        Assert.True(cc.InSlowStart); // cwnd < ssthresh ⇒ wieder Slow Start
    }
}

public class PacerTests
{
    private static long Ticks(double ms) => TimeSpan.FromMilliseconds(ms).Ticks;

    [Fact]
    public void FirstRefill_GrantsFullBurst()
    {
        var pacer = new Pacer();
        pacer.Refill(nowTicks: 0, congestionWindow: 12000, smoothedRtt: TimeSpan.FromMilliseconds(100));
        Assert.Equal(12000, pacer.AvailableBytes); // Burst-Cap = min(cwnd, 10·MDS) = 12000
    }

    [Fact]
    public void Refill_AccumulatesAtRate_ProportionalToElapsedTime()
    {
        var pacer = new Pacer();
        pacer.Refill(0, congestionWindow: 12000, smoothedRtt: TimeSpan.FromMilliseconds(120));
        pacer.OnBytesSent(12000); // Budget auf 0

        // Rate = 1.25 · 12000 / 1_200_000 Ticks = 0.0125 Byte/Tick; über 10 ms (100_000 Ticks) → 1250 Byte.
        pacer.Refill(Ticks(10), congestionWindow: 12000, smoothedRtt: TimeSpan.FromMilliseconds(120));
        Assert.Equal(1250, pacer.AvailableBytes);
    }

    [Fact]
    public void Refill_CapsAtBurst_AfterLongIdle()
    {
        var pacer = new Pacer();
        pacer.Refill(0, 12000, TimeSpan.FromMilliseconds(100));
        pacer.OnBytesSent(12000);

        // Sehr lange Pause: würde weit über den Burst hinaus akkumulieren – wird gedeckelt.
        pacer.Refill(Ticks(100_000), 12000, TimeSpan.FromMilliseconds(100));
        Assert.Equal(12000, pacer.AvailableBytes);
    }

    [Fact]
    public void BurstCap_NeverExceeds_TenDatagrams_EvenForLargeWindow()
    {
        var pacer = new Pacer();
        pacer.Refill(0, congestionWindow: 1_000_000, smoothedRtt: TimeSpan.FromMilliseconds(50));
        Assert.Equal(12000, pacer.AvailableBytes); // 10 · 1200, unabhängig vom großen cwnd
    }

    [Fact]
    public void OverSpending_DrivesBudgetNegative_ReportedAsZero()
    {
        var pacer = new Pacer();
        pacer.Refill(0, congestionWindow: 2000, smoothedRtt: TimeSpan.FromMilliseconds(100));
        Assert.Equal(2400, pacer.AvailableBytes); // Burst-Cap = max(2·MDS, min(cwnd, 10·MDS)) = 2400

        pacer.OnBytesSent(3000); // mehr gesendet als Budget
        Assert.Equal(0, pacer.AvailableBytes); // negativ, aber als 0 gemeldet
    }
}

public class LossRecoveryTests
{
    private static SentPacket Packet(ulong pn, long tick, params Frame[] frames) => new()
    {
        PacketNumber = pn,
        TimeSentTicks = tick,
        AckEliciting = true,
        Size = 1200,
        RetransmittableFrames = frames,
    };

    [Fact]
    public void PacketThreshold_MarksOlderPacketsLost_AndReturnsTheirFrames()
    {
        var lr = new LossRecovery();
        var crypto = new CryptoFrame(0, new byte[] { 1, 2, 3 });

        // Pakete 0..3 senden; 0 trägt ein CRYPTO-Frame.
        lr.OnPacketSent(0, Packet(0, 1000, crypto));
        for (ulong pn = 1; pn <= 3; pn++)
            lr.OnPacketSent(0, Packet(pn, 1000 + (long)pn));

        // ACK für Paket 3 → Paket 0 liegt 3 hinter dem größten Bestätigten ⇒ verloren.
        var ack = AckFrame.FromPacketNumbers([3]);
        List<Frame> lost = lr.OnAckReceived(0, ack, TimeSpan.Zero, nowTicks: 2000);

        Assert.Contains(crypto, lost);
    }

    [Fact]
    public void Ack_UpdatesRtt_FromLargestAcked()
    {
        var lr = new LossRecovery();
        lr.OnPacketSent(0, Packet(0, tick: 0));

        // "now" = 100 ms später (in Ticks).
        long now = TimeSpan.FromMilliseconds(100).Ticks;
        lr.OnAckReceived(0, AckFrame.FromPacketNumbers([0]), TimeSpan.Zero, now);

        Assert.Equal(TimeSpan.FromMilliseconds(100), lr.Rtt.SmoothedRtt);
    }

    [Fact]
    public void ProbeTimeout_ReturnsOldestUnackedFrames()
    {
        var lr = new LossRecovery();
        var crypto = new CryptoFrame(0, new byte[] { 9 });
        lr.OnPacketSent(1, Packet(0, tick: 0, crypto));

        Assert.True(lr.GetProbeTimeoutDeadline() > 0);
        lr.OnProbeTimeoutFired();
        List<Frame> probe = lr.GetProbeFrames(1);
        Assert.Contains(crypto, probe);
        Assert.Equal(1, lr.PtoCount);
    }

    private static long Ms(double ms) => TimeSpan.FromMilliseconds(ms).Ticks;

    /// <summary>
    /// Nicht-ack-eliciting Paket (löst keine RTT-Stichprobe aus), um Verluste gezielt auszulösen.
    /// </summary>
    private static SentPacket Trigger(ulong pn, long tick) => new()
    {
        PacketNumber = pn,
        TimeSentTicks = tick,
        AckEliciting = false,
        Size = 40,
        RetransmittableFrames = [],
    };

    [Fact]
    public void PersistentCongestion_CollapsesWindow_AfterLongLossRun()
    {
        var lr = new LossRecovery { MaxAckDelay = TimeSpan.FromMilliseconds(25) };

        // Erste RTT-Stichprobe: Paket 0 senden, 100 ms später bestätigen ⇒ smoothed_rtt = 100 ms,
        // rttvar = 50 ms ⇒ PC-Dauer = (100 + 200 + 25) · 3 = 975 ms.
        lr.OnPacketSent(0, Packet(0, tick: 0));
        lr.OnAckReceived(0, AckFrame.FromPacketNumbers([0]), TimeSpan.Zero, Ms(100));
        long cwndBefore = lr.Congestion.CongestionWindow;

        // Ack-eliciting Pakete 1..8 über 1050 ms verteilt (alle nach der ersten Stichprobe gesendet).
        for (ulong pn = 1; pn <= 8; pn++)
            lr.OnPacketSent(0, Packet(pn, Ms(200 + (pn - 1) * 150)));

        // Ein späteres, nicht-ack-eliciting Paket 20 bestätigen ⇒ 1..8 gelten per Paketschwelle als verloren.
        lr.OnPacketSent(0, Trigger(20, Ms(1400)));
        lr.OnAckReceived(0, AckFrame.FromPacketNumbers([20]), TimeSpan.Zero, Ms(1400));

        // Spanne 1..8 = 1050 ms > 975 ms ⇒ Persistent Congestion ⇒ Fenster kollabiert auf das Minimum.
        Assert.Equal(NewRenoCongestionControl.MinimumWindow, lr.Congestion.CongestionWindow);
        Assert.True(lr.Congestion.CongestionWindow < cwndBefore);
    }

    [Fact]
    public void PersistentCongestion_NotEstablished_WhenLossSpanTooShort()
    {
        var lr = new LossRecovery { MaxAckDelay = TimeSpan.FromMilliseconds(25) };
        lr.OnPacketSent(0, Packet(0, tick: 0));
        lr.OnAckReceived(0, AckFrame.FromPacketNumbers([0]), TimeSpan.Zero, Ms(100)); // PC-Dauer = 975 ms

        // Pakete 1..5 nur über 200 ms verteilt ⇒ Spanne < PC-Dauer.
        for (ulong pn = 1; pn <= 5; pn++)
            lr.OnPacketSent(0, Packet(pn, Ms(200 + (pn - 1) * 50)));
        lr.OnPacketSent(0, Trigger(20, Ms(500)));
        lr.OnAckReceived(0, AckFrame.FromPacketNumbers([20]), TimeSpan.Zero, Ms(500));

        // Kein PC: Fenster nur durch das Congestion-Event halbiert, aber nicht auf das Minimum kollabiert.
        Assert.True(lr.Congestion.CongestionWindow > NewRenoCongestionControl.MinimumWindow);
    }

    [Fact]
    public void PersistentCongestion_NotEstablished_BeforeFirstRttSample()
    {
        var lr = new LossRecovery { MaxAckDelay = TimeSpan.FromMilliseconds(25) };

        // Ohne je eine RTT-Stichprobe: lange Verlustserie 1..8, ausgelöst durch nicht-ack-eliciting Paket 20.
        for (ulong pn = 1; pn <= 8; pn++)
            lr.OnPacketSent(0, Packet(pn, Ms(200 + (pn - 1) * 150)));
        lr.OnPacketSent(0, Trigger(20, Ms(1400)));
        lr.OnAckReceived(0, AckFrame.FromPacketNumbers([20]), TimeSpan.Zero, Ms(1400));

        // PC darf ohne vorherige RTT-Stichprobe nicht greifen (RFC 9002 §7.6.2).
        Assert.True(lr.Congestion.CongestionWindow > NewRenoCongestionControl.MinimumWindow);
    }
}
