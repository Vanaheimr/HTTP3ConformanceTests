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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// A packet-number space (RFC 9000 §12.3): separate for Initial, Handshake and Application. Assigns
/// ascending packet numbers when sending and remembers received numbers for ACK generation.
/// </summary>
public sealed class PacketNumberSpace
{
    private ulong _nextToSend;
    private readonly SortedSet<ulong> _received = [];

    // Cumulative ECN counters of the received packets of this space (RFC 9000 §13.4.2), reported in the ACK frame.
    private ulong _ect0Count;
    private ulong _ect1Count;
    private ulong _ceCount;

    /// <summary>
    /// Number of received packets with a CE mark (diagnostics/test).
    /// </summary>
    public ulong ReceivedCeCount => _ceCount;

    /// <summary>
    /// Largest packet number acknowledged by the peer (for choosing the PN encoding length); -1 = none.
    /// </summary>
    public long LargestAckedByPeer { get; private set; } = -1;

    /// <summary>
    /// Largest packet number received so far (for PN reconstruction on receive); -1 = none.
    /// </summary>
    public long LargestReceived => _received.Count == 0 ? -1 : (long)_received.Max;

    /// <summary>
    /// There are received packets not yet acknowledged via ACK.
    /// </summary>
    public bool AckPending { get; private set; }

    /// <summary>
    /// <c>true</c> when reception from packet number 0 is gap-free (i.e. exactly {0,1,…,Max}, no
    /// missing numbers). Packet numbers start at 0 per space (RFC 9000 §12.3), so this holds exactly
    /// when the number of received packets is <c>Max+1</c>. Usage: the server thereby detects that it
    /// has received all 0-RTT packets (RFC 9001 §4.9.3, "keeping track of missing packet numbers").
    /// </summary>
    public bool IsContiguousFromZero => _received.Count > 0 && (ulong)_received.Count == _received.Max + 1;

    /// <summary>
    /// Assigns the next packet number to send.
    /// </summary>
    public ulong NextPacketNumber() => _nextToSend++;

    /// <summary>
    /// Records a successfully unprotected, received packet number along with its ECN codepoint.
    /// </summary>
    public void RecordReceived(ulong packetNumber, EcnCodepoint ecn = EcnCodepoint.NotEct)
    {
        _received.Add(packetNumber);
        AckPending = true;
        switch (ecn)
        {
            case EcnCodepoint.Ect0: _ect0Count++; break;
            case EcnCodepoint.Ect1: _ect1Count++; break;
            case EcnCodepoint.Ce: _ceCount++; break;
        }
    }

    /// <summary>
    /// Processes a received ACK frame (updates the largest acknowledged number).
    /// </summary>
    public void OnAckReceived(ulong largestAcknowledged)
    {
        if ((long)largestAcknowledged > LargestAckedByPeer)
            LargestAckedByPeer = (long)largestAcknowledged;
    }

    /// <summary>
    /// Builds an ACK frame over all packets received so far and marks the ACKs as sent.
    /// Returns <c>null</c> when there is nothing to acknowledge.
    /// </summary>
    public AckFrame? BuildAck(ulong ackDelay = 0)
    {
        if (_received.Count == 0)
            return null;
        AckPending = false;

        // Once ECN-marked packets have been received, every ACK MUST carry the cumulative counters
        // (type 0x03, RFC 9000 §13.4.2). Without ECN marks, the simple ACK (0x02) remains.
        EcnCounts? ecn = (_ect0Count | _ect1Count | _ceCount) != 0
            ? new EcnCounts(_ect0Count, _ect1Count, _ceCount)
            : null;
        return AckFrame.FromPacketNumbers(_received, ackDelay) with { Ecn = ecn };
    }
}
