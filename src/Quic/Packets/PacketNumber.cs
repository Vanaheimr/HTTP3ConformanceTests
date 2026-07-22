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

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;

/// <summary>
/// Kodierung und Rekonstruktion von QUIC-Paketnummern (RFC 9000, §17.1 und Anhang A).
/// <para>
/// Auf dem Draht werden nur die niederwertigen 1–4 Bytes der Paketnummer übertragen. Der Empfänger
/// rekonstruiert die volle 62-Bit-Nummer relativ zur größten bislang bestätigten Paketnummer.
/// </para>
/// </summary>
public static class PacketNumber
{
    /// <summary>
    /// Obergrenze des Paketnummernraums (2^62).
    /// </summary>
    private const ulong PacketNumberLimit = 1UL << 62;

    /// <summary>
    /// Bestimmt die minimale Anzahl Bytes (1–4), mit der <paramref name="packetNumber"/> so kodiert
    /// werden kann, dass der Empfänger sie relativ zu <paramref name="largestAcked"/> eindeutig
    /// rekonstruiert. Vor der ersten Bestätigung (<paramref name="largestAcked"/> = -1) wird die
    /// volle benötigte Länge gewählt.
    /// </summary>
    public static int EncodeLength(ulong packetNumber, long largestAcked)
    {
        // Anzahl noch unbestätigter, fortlaufender Paketnummern inkl. der neuen (num_unacked).
        ulong range = largestAcked < 0 ? packetNumber + 1 : packetNumber - (ulong)largestAcked;

        // RFC 9000 A.2: min_bits = log2(range) + 1, num_bytes = ceil(min_bits / 8).
        // Das ergibt die Schwellen range <= 2^7, 2^15, 2^23 (Grenzen inklusive).
        if (range <= (1UL << 7)) return 1;
        if (range <= (1UL << 15)) return 2;
        if (range <= (1UL << 23)) return 3;
        return 4;
    }

    /// <summary>
    /// Schreibt die niederwertigen <paramref name="length"/> Bytes von <paramref name="packetNumber"/> big-endian.
    /// </summary>
    public static void Encode(Span<byte> destination, ulong packetNumber, int length)
    {
        if (length is < 1 or > 4)
            throw new ArgumentOutOfRangeException(nameof(length));
        for (int i = 0; i < length; i++)
            destination[i] = (byte)(packetNumber >> (8 * (length - 1 - i)));
    }

    /// <summary>
    /// Rekonstruiert die volle Paketnummer aus der verkürzten Wire-Kodierung
    /// (RFC 9000, Anhang A.3 – <c>DecodePacketNumber</c>).
    /// </summary>
    /// <param name="truncated">Die auf <paramref name="length"/> Bytes gekürzt empfangene Nummer.</param>
    /// <param name="length">Anzahl empfangener Bytes (1–4).</param>
    /// <param name="largestAcked">Größte bislang erfolgreich verarbeitete Paketnummer (-1 = noch keine).</param>
    public static ulong Decode(uint truncated, int length, long largestAcked)
    {
        int pnBits = length * 8;
        ulong pnWin = 1UL << pnBits;
        ulong pnHalfWin = pnWin / 2;
        ulong pnMask = pnWin - 1;

        // "expected" ist die nächste erwartete Paketnummer.
        ulong expected = (ulong)(largestAcked + 1);
        ulong candidate = (expected & ~pnMask) | truncated;

        if (candidate + pnHalfWin <= expected && candidate + pnWin < PacketNumberLimit)
            return candidate + pnWin;
        if (candidate > expected + pnHalfWin && candidate >= pnWin)
            return candidate - pnWin;
        return candidate;
    }
}
