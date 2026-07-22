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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Recovery;

/// <summary>
/// NewReno-Congestion-Control nach RFC 9002 §7 / Anhang B: Slow Start, Congestion Avoidance und
/// Recovery über ein Congestion Window (in Bytes). Bewusst schlicht gehalten (kein CUBIC/BBR).
/// </summary>
public sealed class NewRenoCongestionControl
{
    private const int MaxDatagramSize = 1200;
    private const double LossReductionFactor = 0.5;

    /// <summary>
    /// Minimales Fenster (RFC 9002: kMinimumWindow = 2 · max_datagram_size).
    /// </summary>
    public static int MinimumWindow => 2 * MaxDatagramSize;

    /// <summary>
    /// Startfenster (RFC 9002: kInitialWindow = min(10·MDS, max(2·MDS, 14720))).
    /// </summary>
    public static int InitialWindow => Math.Min(10 * MaxDatagramSize, Math.Max(2 * MaxDatagramSize, 14720));

    private long _recoveryStartTimeTicks = -1;

    public int CongestionWindow { get; private set; } = InitialWindow;
    public long BytesInFlight { get; private set; }
    public long SlowStartThreshold { get; private set; } = long.MaxValue;

    public bool InSlowStart => CongestionWindow < SlowStartThreshold;

    /// <summary>
    /// Es darf gesendet werden, solange die Daten im Flug unter dem Fenster liegen.
    /// </summary>
    public bool CanSend(int bytes) => BytesInFlight + bytes <= CongestionWindow;

    /// <summary>
    /// Verfügbares Sendevolumen (Fenster minus Daten im Flug).
    /// </summary>
    public long Available => Math.Max(0, CongestionWindow - BytesInFlight);

    public void OnPacketSent(int bytes) => BytesInFlight += bytes;

    /// <summary>
    /// Beim Verwerfen eines Packet-Number-Space (RFC 9002 §6.4): Bytes im Flug ohne Congestion-Event abziehen.
    /// </summary>
    public void OnPacketDiscarded(int bytes) => BytesInFlight = Math.Max(0, BytesInFlight - bytes);

    /// <summary>
    /// Ein Paket wurde bestätigt (RFC 9002 §7.3.1/§B.5).
    /// </summary>
    public void OnPacketAcked(int bytes, long sentTimeTicks)
    {
        BytesInFlight = Math.Max(0, BytesInFlight - bytes);

        // Bestätigungen für vor Recovery gesendete Pakete erhöhen das Fenster nicht.
        if (_recoveryStartTimeTicks >= 0 && sentTimeTicks <= _recoveryStartTimeTicks)
            return;

        if (InSlowStart)
            CongestionWindow += bytes;
        else
            CongestionWindow += (int)((long)MaxDatagramSize * bytes / CongestionWindow);
    }

    /// <summary>
    /// Paketverlust erkannt (RFC 9002 §7.3.2/§B.6): Fenster halbieren, Recovery beginnen.
    /// </summary>
    public void OnPacketsLost(int bytes, long largestLostSentTimeTicks, long nowTicks)
    {
        BytesInFlight = Math.Max(0, BytesInFlight - bytes);
        OnCongestionEvent(largestLostSentTimeTicks, nowTicks);
    }

    /// <summary>
    /// Reaktion auf eine ECN-CE-Meldung (RFC 9002 §7.3): Der Sender behandelt einen gestiegenen CE-Zähler wie
    /// einen Verlust – Fenster halbieren, Recovery beginnen. <paramref name="largestAckedSentTimeTicks"/> ist der
    /// Sendezeitpunkt des größten quittierten Pakets, damit pro Recovery-Periode nur einmal verkleinert wird.
    /// </summary>
    public void OnEcnCongestionEvent(long largestAckedSentTimeTicks, long nowTicks)
        => OnCongestionEvent(largestAckedSentTimeTicks, nowTicks);

    private void OnCongestionEvent(long sentTimeTicks, long nowTicks)
    {
        // Innerhalb einer laufenden Recovery-Periode kein erneutes Verkleinern.
        if (_recoveryStartTimeTicks >= 0 && sentTimeTicks <= _recoveryStartTimeTicks)
            return;

        _recoveryStartTimeTicks = nowTicks;
        SlowStartThreshold = (long)(CongestionWindow * LossReductionFactor);
        CongestionWindow = (int)Math.Max(SlowStartThreshold, MinimumWindow);
    }

    /// <summary>
    /// Persistent Congestion erkannt (RFC 9002 §7.6/§B.8): Das Fenster kollabiert auf das Minimum und
    /// die Recovery-Periode wird zurückgesetzt (<c>congestion_recovery_start_time = 0</c>), sodass die
    /// nächsten Bestätigungen wieder in Slow Start hochlaufen.
    /// </summary>
    public void OnPersistentCongestion()
    {
        CongestionWindow = MinimumWindow;
        _recoveryStartTimeTicks = -1;
    }
}
