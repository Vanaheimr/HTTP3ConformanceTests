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

using org.GraphDefined.Vanaheimr.Hermod.Quic.Core.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;

/// <summary>
/// Ein zusammenhängender, bestätigter Paketnummernbereich [Smallest, Largest] (inklusive).
/// </summary>
public readonly record struct PacketNumberRange(ulong Largest, ulong Smallest)
{
    public ulong Count => Largest - Smallest + 1;
}

/// <summary>
/// Die drei ECN-Zähler eines ACK-Frames vom Typ 0x03 (RFC 9000 §19.3.2).
/// </summary>
public readonly record struct EcnCounts(ulong Ect0, ulong Ect1, ulong CongestionExperienced);

/// <summary>
/// ACK-Frame (Typ 0x02/0x03, RFC 9000 §19.3). Bestätigt empfangene Pakete als absteigend sortierte,
/// nicht überlappende Bereiche. Die Wire-Kodierung nutzt relative Gap-/Längenwerte; dieses Modell
/// hält stattdessen die absoluten Bereiche und rechnet beim Schreiben/Lesen um.
/// </summary>
public sealed record AckFrame(
    IReadOnlyList<PacketNumberRange> Ranges,
    ulong AckDelay,
    EcnCounts? Ecn = null) : Frame
{
    /// <summary>
    /// Größte bestätigte Paketnummer (aus dem ersten, höchsten Bereich).
    /// </summary>
    public ulong LargestAcknowledged => Ranges[0].Largest;

    /// <summary>
    /// Baut ein ACK-Frame aus einer Menge empfangener Paketnummern, indem aufeinanderfolgende
    /// Nummern zu Bereichen zusammengefasst werden (absteigend sortiert).
    /// </summary>
    public static AckFrame FromPacketNumbers(IEnumerable<ulong> packetNumbers, ulong ackDelay = 0)
    {
        List<ulong> sorted = packetNumbers.Distinct().OrderByDescending(x => x).ToList();
        if (sorted.Count == 0)
            throw new ArgumentException("Mindestens eine Paketnummer erforderlich.", nameof(packetNumbers));

        var ranges = new List<PacketNumberRange>();
        int i = 0;
        while (i < sorted.Count)
        {
            ulong largest = sorted[i];
            ulong smallest = largest;
            while (i + 1 < sorted.Count && smallest > 0 && sorted[i + 1] == smallest - 1)
            {
                smallest = sorted[i + 1];
                i++;
            }
            ranges.Add(new PacketNumberRange(largest, smallest));
            i++;
        }
        return new AckFrame(ranges, ackDelay);
    }

    public override void Write(ref BufferWriter writer)
    {
        writer.WriteVarInt(Ecn is null ? FrameType.AckNoEcn : FrameType.AckEcn);
        writer.WriteVarInt(Ranges[0].Largest);
        writer.WriteVarInt(AckDelay);
        writer.WriteVarInt((ulong)(Ranges.Count - 1));                 // ACK Range Count
        writer.WriteVarInt(Ranges[0].Largest - Ranges[0].Smallest);    // First ACK Range

        for (int i = 1; i < Ranges.Count; i++)
        {
            // largest_i = previous_smallest - gap - 2  =>  gap = previous_smallest - largest_i - 2
            ulong gap = Ranges[i - 1].Smallest - Ranges[i].Largest - 2;
            writer.WriteVarInt(gap);
            writer.WriteVarInt(Ranges[i].Largest - Ranges[i].Smallest); // ACK Range Length
        }

        if (Ecn is { } ecn)
        {
            writer.WriteVarInt(ecn.Ect0);
            writer.WriteVarInt(ecn.Ect1);
            writer.WriteVarInt(ecn.CongestionExperienced);
        }
    }

    /// <summary>
    /// Parst den Frame-Rumpf. <paramref name="hasEcn"/> ergibt sich aus dem Typ (0x03).
    /// </summary>
    public static bool TryReadBody(ref BufferReader reader, bool hasEcn, out AckFrame? frame)
    {
        frame = null;
        if (!reader.TryReadVarInt(out ulong largest) ||
            !reader.TryReadVarInt(out ulong ackDelay) ||
            !reader.TryReadVarInt(out ulong rangeCount) ||
            !reader.TryReadVarInt(out ulong firstAckRange) ||
            firstAckRange > largest)
            return false;

        var ranges = new List<PacketNumberRange>((int)Math.Min(rangeCount + 1, 1024));
        ulong smallest = largest - firstAckRange;
        ranges.Add(new PacketNumberRange(largest, smallest));

        for (ulong i = 0; i < rangeCount; i++)
        {
            if (!reader.TryReadVarInt(out ulong gap) || !reader.TryReadVarInt(out ulong ackRangeLength))
                return false;

            // largest_next = previous_smallest - gap - 2; jede berechnete Nummer muss >= 0 bleiben.
            if (smallest < gap + 2)
                return false; // FRAME_ENCODING_ERROR: negativer Paketnummernwert
            ulong nextLargest = smallest - gap - 2;
            if (ackRangeLength > nextLargest)
                return false;
            ulong nextSmallest = nextLargest - ackRangeLength;

            ranges.Add(new PacketNumberRange(nextLargest, nextSmallest));
            smallest = nextSmallest;
        }

        EcnCounts? ecn = null;
        if (hasEcn)
        {
            if (!reader.TryReadVarInt(out ulong ect0) ||
                !reader.TryReadVarInt(out ulong ect1) ||
                !reader.TryReadVarInt(out ulong ce))
                return false;
            ecn = new EcnCounts(ect0, ect1, ce);
        }

        frame = new AckFrame(ranges, ackDelay, ecn);
        return true;
    }
}
