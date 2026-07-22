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
/// Token-Bucket-Pacer nach RFC 9002 §7.7. Verteilt die gesendeten Bytes zeitlich, damit nicht das
/// gesamte Congestion Window als Burst rausgeht (was Warteschlangen und Verluste provoziert). Die Rate
/// ist <c>N · congestion_window / smoothed_rtt</c> (N = 1.25); das Budget wird auf einen kleinen Burst
/// gedeckelt, sodass nach Leerlauf nicht beliebig viel „nachgeholt" werden kann.
/// <para>Zeitpunkte sind <see cref="TimeSpan.Ticks"/> (100 ns) einer monotonen Uhr.</para>
/// </summary>
public sealed class Pacer
{
    /// <summary>
    /// Pacing-Gain N (RFC 9002 §7.7): erlaubt 25 % über der reinen cwnd/RTT-Rate.
    /// </summary>
    private const double PacingGain = 1.25;

    private const int MaxDatagramSize = 1200;

    private double _budget;              // verfügbares Sendebudget in Bytes (darf transient negativ sein)
    private long _lastRefillTicks = -1;

    /// <summary>
    /// Aktuelles Sendebudget in Bytes (auf 0 geklemmt für den Aufrufer).
    /// </summary>
    public long AvailableBytes => (long)Math.Max(0, _budget);

    /// <summary>
    /// Füllt das Budget anhand der seit dem letzten Aufruf verstrichenen Zeit und der aktuellen Rate
    /// nach. Beim ersten Aufruf wird ein voller Burst gutgeschrieben.
    /// </summary>
    public void Refill(long nowTicks, long congestionWindow, TimeSpan smoothedRtt)
    {
        long burstCap = BurstCap(congestionWindow);
        if (_lastRefillTicks < 0)
        {
            _lastRefillTicks = nowTicks;
            _budget = burstCap; // anfangs darf ein voller Burst raus (Initial Window)
            return;
        }

        long elapsed = nowTicks - _lastRefillTicks;
        if (elapsed <= 0)
            return;
        _lastRefillTicks = nowTicks;

        _budget = Math.Min(burstCap, _budget + BytesPerTick(congestionWindow, smoothedRtt) * elapsed);
    }

    /// <summary>
    /// Bucht <paramref name="bytes"/> gesendete Bytes ab (Budget darf dabei negativ werden).
    /// </summary>
    public void OnBytesSent(int bytes) => _budget -= bytes;

    /// <summary>
    /// Bytes pro Tick bei aktueller Rate; ohne gültige RTT wird nicht gepact (unbegrenzt).
    /// </summary>
    private static double BytesPerTick(long congestionWindow, TimeSpan smoothedRtt)
    {
        long rttTicks = smoothedRtt.Ticks;
        if (rttTicks <= 0)
            return double.MaxValue;
        return PacingGain * congestionWindow / rttTicks;
    }

    /// <summary>
    /// Burst-Kappung: erlaubt kurze Bursts (mind. 2 Datagramme), aber höchstens ein Initial-Window
    /// (≈ 10 Datagramme) bzw. das aktuelle Fenster, je nachdem, was kleiner ist.
    /// </summary>
    private static long BurstCap(long congestionWindow)
        => Math.Max(2 * MaxDatagramSize, Math.Min(congestionWindow, 10 * MaxDatagramSize));
}
