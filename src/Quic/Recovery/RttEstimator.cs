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
/// RTT-Schätzung nach RFC 9002 §5: min_rtt, smoothed_rtt und rttvar aus RTT-Stichproben, plus die
/// Berechnung des Probe Timeout (PTO, §6.2.1). Werte als <see cref="TimeSpan"/>.
/// </summary>
public sealed class RttEstimator
{
    /// <summary>
    /// Timer-Granularität (RFC 9002: kGranularity = 1 ms).
    /// </summary>
    public static readonly TimeSpan Granularity = TimeSpan.FromMilliseconds(1);

    /// <summary>
    /// Anfangs-RTT vor der ersten Stichprobe (RFC 9002: kInitialRtt = 333 ms).
    /// </summary>
    public static readonly TimeSpan InitialRtt = TimeSpan.FromMilliseconds(333);

    private bool _hasSample;

    public TimeSpan LatestRtt { get; private set; }
    public TimeSpan MinRtt { get; private set; }
    public TimeSpan SmoothedRtt { get; private set; } = InitialRtt;
    public TimeSpan RttVar { get; private set; } = InitialRtt / 2;

    /// <summary>
    /// Verarbeitet eine RTT-Stichprobe (RFC 9002 §5.3). <paramref name="ackDelay"/> ist die vom Peer
    /// gemeldete ACK-Verzögerung, begrenzt durch <paramref name="maxAckDelay"/> (nach dem Handshake).
    /// </summary>
    public void AddSample(TimeSpan rttSample, TimeSpan ackDelay, TimeSpan maxAckDelay)
    {
        LatestRtt = rttSample;

        if (!_hasSample)
        {
            MinRtt = rttSample;
            SmoothedRtt = rttSample;
            RttVar = rttSample / 2;
            _hasSample = true;
            return;
        }

        MinRtt = rttSample < MinRtt ? rttSample : MinRtt;

        // ack_delay begrenzen und nur abziehen, wenn die Stichprobe dadurch nicht unter min_rtt fällt.
        TimeSpan adjustedAckDelay = ackDelay < maxAckDelay ? ackDelay : maxAckDelay;
        TimeSpan adjustedRtt = rttSample;
        if (rttSample >= MinRtt + adjustedAckDelay)
            adjustedRtt = rttSample - adjustedAckDelay;

        TimeSpan diff = SmoothedRtt > adjustedRtt ? SmoothedRtt - adjustedRtt : adjustedRtt - SmoothedRtt;
        RttVar = (3 * RttVar + diff) / 4;                  // 3/4 rttvar + 1/4 |smoothed - adjusted|
        SmoothedRtt = (7 * SmoothedRtt + adjustedRtt) / 8; // 7/8 smoothed + 1/8 adjusted
    }

    /// <summary>
    /// Probe Timeout (RFC 9002 §6.2.1): smoothed_rtt + max(4·rttvar, kGranularity) + max_ack_delay.
    /// </summary>
    public TimeSpan GetProbeTimeout(TimeSpan maxAckDelay)
    {
        if (!_hasSample)
            return 2 * InitialRtt; // vor der ersten Stichprobe

        TimeSpan variation = 4 * RttVar;
        if (variation < Granularity)
            variation = Granularity;
        return SmoothedRtt + variation + maxAckDelay;
    }

    /// <summary>
    /// Verzögerung, ab der ein Paket als per Zeitschwelle verloren gilt (RFC 9002 §6.1.2).
    /// </summary>
    public TimeSpan LossDelay()
    {
        // kTimeThreshold = 9/8 · max(latest_rtt, smoothed_rtt), mindestens kGranularity.
        TimeSpan baseRtt = LatestRtt > SmoothedRtt ? LatestRtt : SmoothedRtt;
        TimeSpan delay = 9 * baseRtt / 8;
        return delay > Granularity ? delay : Granularity;
    }
}
