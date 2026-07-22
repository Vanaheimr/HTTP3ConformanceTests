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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Recovery;

/// <summary>
/// Ein gesendetes Paket, das für Loss Detection und Retransmission verfolgt wird.
/// </summary>
public sealed class SentPacket
{
    public required ulong PacketNumber { get; init; }
    public required long TimeSentTicks { get; init; }
    public required bool AckEliciting { get; init; }
    public required int Size { get; init; }

    /// <summary>
    /// Bei Verlust erneut zu sendende Frames (CRYPTO, STREAM). ACK/Flow-Control werden neu abgeleitet.
    /// </summary>
    public required IReadOnlyList<Frame> RetransmittableFrames { get; init; }
}

/// <summary>
/// Loss Detection und Retransmission-Buchführung nach RFC 9002 §6 – getrennt je Packet-Number-Space
/// (Initial/Handshake/Application). Erkennt Verluste per Paket- und Zeitschwelle, aktualisiert den
/// RTT-Schätzer und den Congestion Controller und liefert die Frames verlorener Pakete zurück.
/// Zeitpunkte sind <see cref="TimeSpan.Ticks"/> (100 ns) einer monotonen Uhr.
/// </summary>
public sealed class LossRecovery
{
    private const int PacketThreshold = 3;

    /// <summary>
    /// PTO-Multiplikator für die Persistent-Congestion-Dauer (RFC 9002 §7.6, empfohlen: 3).
    /// </summary>
    private const int PersistentCongestionThreshold = 3;

    private sealed class SpaceState
    {
        public readonly SortedDictionary<ulong, SentPacket> Sent = [];
        public long LargestAcked = -1;
        public long LossTimeTicks = -1;
        public ulong LargestCeCount; // höchster bisher gemeldeter ECN-CE-Zähler (RFC 9002 §A.7)
    }

    private readonly SpaceState[] _spaces = [new(), new(), new()];

    /// <summary>
    /// Zeitpunkt der ersten RTT-Stichprobe; vorher greift Persistent Congestion nicht (RFC 9002 §7.6.2).
    /// </summary>
    private long _firstRttSampleTicks = -1;

    public RttEstimator Rtt { get; } = new();
    public NewRenoCongestionControl Congestion { get; } = new();
    public TimeSpan MaxAckDelay { get; set; } = TimeSpan.FromMilliseconds(25);

    /// <summary>
    /// Zeitpunkt des zuletzt gesendeten ack-eliciting Pakets (für PTO); -1 = keines im Flug.
    /// </summary>
    public long LastAckElicitingSentTicks { get; private set; } = -1;

    public int PtoCount { get; private set; }

    /// <summary>
    /// Verwirft den gesamten Loss-Recovery-Zustand eines Packet-Number-Space (RFC 9002 §6.4), wenn dessen
    /// Schutzschlüssel verworfen werden (Initial/Handshake nach dem Handshake): die noch nicht bestätigten
    /// Pakete gelten nicht mehr, ihre Bytes werden aus <c>bytes_in_flight</c> genommen.
    /// </summary>
    public void DiscardSpace(int space)
    {
        SpaceState st = _spaces[space];
        foreach (SentPacket sp in st.Sent.Values)
            if (sp.AckEliciting)
                Congestion.OnPacketDiscarded(sp.Size);
        st.Sent.Clear();
        st.LargestAcked = -1;
        st.LossTimeTicks = -1;
        UpdateInFlightMarker();
    }

    public void OnPacketSent(int space, SentPacket packet)
    {
        _spaces[space].Sent[packet.PacketNumber] = packet;
        if (packet.AckEliciting)
        {
            Congestion.OnPacketSent(packet.Size);
            LastAckElicitingSentTicks = packet.TimeSentTicks;
        }
    }

    /// <summary>
    /// Verarbeitet ein empfangenes ACK: entfernt bestätigte Pakete, aktualisiert RTT/Congestion Window
    /// und erkennt verlorene Pakete. Gibt die erneut zu sendenden Frames verlorener Pakete zurück.
    /// </summary>
    public List<Frame> OnAckReceived(int space, AckFrame ack, TimeSpan ackDelay, long nowTicks)
    {
        SpaceState st = _spaces[space];
        if ((long)ack.LargestAcknowledged > st.LargestAcked)
            st.LargestAcked = (long)ack.LargestAcknowledged;

        SentPacket? largestNewlyAcked = null;
        foreach (PacketNumberRange range in ack.Ranges)
        {
            for (ulong pn = range.Smallest; pn <= range.Largest; pn++)
            {
                if (!st.Sent.Remove(pn, out SentPacket? sp))
                    continue;
                Congestion.OnPacketAcked(sp.Size, sp.TimeSentTicks);
                if (largestNewlyAcked is null || sp.PacketNumber > largestNewlyAcked.PacketNumber)
                    largestNewlyAcked = sp;
            }
        }

        // RTT nur aus dem größten, neu bestätigten und ack-eliciting Paket ableiten.
        if (largestNewlyAcked is { AckEliciting: true } &&
            largestNewlyAcked.PacketNumber == ack.LargestAcknowledged)
        {
            var rttSample = TimeSpan.FromTicks(Math.Max(0, nowTicks - largestNewlyAcked.TimeSentTicks));
            Rtt.AddSample(rttSample, ackDelay, MaxAckDelay);
            if (_firstRttSampleTicks < 0)
                _firstRttSampleTicks = nowTicks; // RFC 9002 §B.8: first_rtt_sample
        }

        // ECN (RFC 9002 §A.7 ProcessECN): meldet das ACK einen gestiegenen CE-Zähler, gilt das als Congestion.
        if (ack.Ecn is { } ecn && ecn.CongestionExperienced > st.LargestCeCount)
        {
            st.LargestCeCount = ecn.CongestionExperienced;
            long sentTime = largestNewlyAcked?.TimeSentTicks ?? nowTicks;
            Congestion.OnEcnCongestionEvent(sentTime, nowTicks);
        }

        PtoCount = 0;
        UpdateInFlightMarker();
        return DetectLostPackets(space, nowTicks);
    }

    private List<Frame> DetectLostPackets(int space, long nowTicks)
    {
        SpaceState st = _spaces[space];
        var lostFrames = new List<Frame>();
        var lostAckEliciting = new List<SentPacket>();
        long lossDelayTicks = Rtt.LossDelay().Ticks;
        long lostSendThreshold = nowTicks - lossDelayTicks;
        st.LossTimeTicks = -1;
        long largestLostTime = -1;
        int lostBytes = 0;

        foreach (SentPacket sp in st.Sent.Values.ToList())
        {
            if ((long)sp.PacketNumber >= st.LargestAcked)
                continue; // nur ältere als das größte bestätigte Paket

            bool lostByThreshold = (long)sp.PacketNumber <= st.LargestAcked - PacketThreshold;
            bool lostByTime = sp.TimeSentTicks <= lostSendThreshold;

            if (lostByThreshold || lostByTime)
            {
                st.Sent.Remove(sp.PacketNumber);
                lostFrames.AddRange(sp.RetransmittableFrames);
                if (sp.AckEliciting)
                {
                    lostBytes += sp.Size;
                    largestLostTime = Math.Max(largestLostTime, sp.TimeSentTicks);
                    lostAckEliciting.Add(sp);
                }
            }
            else
            {
                long t = sp.TimeSentTicks + lossDelayTicks;
                st.LossTimeTicks = st.LossTimeTicks < 0 ? t : Math.Min(st.LossTimeTicks, t);
            }
        }

        if (lostBytes > 0)
            Congestion.OnPacketsLost(lostBytes, largestLostTime, nowTicks);
        DetectPersistentCongestion(lostAckEliciting);
        return lostFrames;
    }

    /// <summary>
    /// Prüft Persistent Congestion (RFC 9002 §7.6.2): Kollabiert das Fenster, wenn zwei ack-eliciting
    /// Pakete verloren sind, dazwischen nichts bestätigt wurde und ihr Sende-Abstand die Persistent-
    /// Congestion-Dauer übersteigt – und beide nach der ersten RTT-Stichprobe gesendet wurden.
    /// <para>Konservative Näherung: „nichts dazwischen bestätigt" wird über konsekutive Paketnummern der
    /// verlorenen (stets ack-eliciting) Pakete geprüft. Eine Lücke (bestätigtes oder noch fliegendes
    /// Paket) unterbricht den Lauf; ein dazwischenliegendes reines ACK-Paket führt höchstens zu einer
    /// verpassten – nie einer falschen – Erkennung.</para>
    /// </summary>
    private void DetectPersistentCongestion(List<SentPacket> lostAckEliciting)
    {
        if (_firstRttSampleTicks < 0)
            return; // erst nach der ersten RTT-Stichprobe

        // Nur Pakete berücksichtigen, die nach der ersten RTT-Stichprobe gesendet wurden (RFC 9002 §B.8).
        List<SentPacket> candidates = lostAckEliciting
            .Where(p => p.TimeSentTicks > _firstRttSampleTicks)
            .OrderBy(p => p.PacketNumber)
            .ToList();
        if (candidates.Count < 2)
            return;

        long pcDuration = Rtt.GetProbeTimeout(MaxAckDelay).Ticks * PersistentCongestionThreshold;

        // Längsten Lauf konsekutiver Paketnummern finden und dessen Zeitspanne prüfen.
        int runStart = 0;
        for (int i = 1; i <= candidates.Count; i++)
        {
            bool endOfRun = i == candidates.Count ||
                            candidates[i].PacketNumber != candidates[i - 1].PacketNumber + 1;
            if (!endOfRun)
                continue;

            SentPacket first = candidates[runStart];
            SentPacket last = candidates[i - 1];
            if (last != first && last.TimeSentTicks - first.TimeSentTicks > pcDuration)
            {
                Congestion.OnPersistentCongestion();
                return;
            }
            runStart = i;
        }
    }

    /// <summary>
    /// PTO-Deadline (RFC 9002 §6.2): letzter ack-eliciting Sendezeitpunkt + PTO·2^ptoCount. -1 = kein Timer.
    /// </summary>
    public long GetProbeTimeoutDeadline()
    {
        if (LastAckElicitingSentTicks < 0)
            return -1;
        long pto = Rtt.GetProbeTimeout(MaxAckDelay).Ticks << PtoCount;
        return LastAckElicitingSentTicks + pto;
    }

    /// <summary>
    /// Erhöht den PTO-Backoff-Zähler (bei abgelaufener PTO aufzurufen).
    /// </summary>
    public void OnProbeTimeoutFired() => PtoCount++;

    /// <summary>
    /// Liefert die Frames des ältesten noch unbestätigten Pakets eines Space zur erneuten Übertragung
    /// (Probe gegen Tail Loss). Leer, wenn nichts aussteht.
    /// </summary>
    public List<Frame> GetProbeFrames(int space)
    {
        foreach (SentPacket sp in _spaces[space].Sent.Values)
            if (sp.RetransmittableFrames.Count > 0)
                return [.. sp.RetransmittableFrames];
        return [];
    }

    /// <summary>
    /// Wird bei abgelehntem 0-RTT aufgerufen (RFC 9001 §4.6.2): entfernt alle als 0-RTT gesendeten (nie
    /// bestätigten) Pakete – erkennbar an <paramref name="maxZeroRttPacketNumber"/>, da 0-RTT- vor
    /// 1-RTT-Paketnummern liegen – aus der Verlustverfolgung und gibt ihre Frames zur sofortigen erneuten
    /// Übertragung über 1-RTT zurück. So entfällt die Wartezeit auf Zeitschwelle/PTO, und weil die Pakete
    /// aus der Sent-Liste verschwinden, werden sie nicht zusätzlich als „verloren" doppelt gesendet.
    /// </summary>
    public List<Frame> OnZeroRttRejected(int space, ulong maxZeroRttPacketNumber)
    {
        SpaceState st = _spaces[space];
        var frames = new List<Frame>();
        foreach (ulong pn in st.Sent.Keys.Where(pn => pn <= maxZeroRttPacketNumber).ToList())
            if (st.Sent.Remove(pn, out SentPacket? sp))
                frames.AddRange(sp.RetransmittableFrames);
        UpdateInFlightMarker();
        return frames;
    }

    private void UpdateInFlightMarker()
    {
        foreach (SpaceState st in _spaces)
            foreach (SentPacket sp in st.Sent.Values)
                if (sp.AckEliciting)
                    return; // es gibt noch ack-eliciting Pakete im Flug
        LastAckElicitingSentTicks = -1;
    }
}
